/*! \file    sdp-utils.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SDP utilities
 * \details  Implementation of an internal SDP representation. Allows
 * to parse SDP strings to an internal janus_sdp object, the manipulation
 * of such object by playing with its properties, and a serialization
 * to an SDP string that can be passed around. Since they don't have any
 * core dependencies, these utilities can be used by plugins as well.
 *
 * \ingroup core
 * \ref core
 */

#include <string.h>

#include "sdp-utils.h"
#include "rtp.h"
#include "utils.h"
#include "debug.h"

/* Preferred codecs when negotiating audio/video, and number of supported codecs */
const char *janus_preferred_audio_codecs[] = {
	"opus", "multiopus", "pcmu", "pcma", "g722", "l16-48", "l16", "isac16", "isac32"
};
uint janus_audio_codecs = sizeof(janus_preferred_audio_codecs)/sizeof(*janus_preferred_audio_codecs);
const char *janus_preferred_video_codecs[] = {
	"vp8", "vp9", "h264", "av1", "h265"
};
uint janus_video_codecs = sizeof(janus_preferred_video_codecs)/sizeof(*janus_preferred_video_codecs);

/* Reference counters management */
void janus_sdp_destroy(janus_sdp *sdp) {
	if(!sdp || !g_atomic_int_compare_and_exchange(&sdp->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&sdp->ref);
}

void janus_sdp_mline_destroy(janus_sdp_mline *m) {
	if(!m || !g_atomic_int_compare_and_exchange(&m->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&m->ref);
}

void janus_sdp_attribute_destroy(janus_sdp_attribute *a) {
	if(!a || !g_atomic_int_compare_and_exchange(&a->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&a->ref);
}

/* Internal frees */
static void janus_sdp_free(const janus_refcount *sdp_ref) {
	janus_sdp *sdp = janus_refcount_containerof(sdp_ref, janus_sdp, ref);
	/* This SDP instance can be destroyed, free all the resources */
	g_free(sdp->o_name);
	g_free(sdp->o_addr);
	g_free(sdp->s_name);
	g_free(sdp->c_addr);
	GList *temp = sdp->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		janus_sdp_attribute_destroy(a);
		temp = temp->next;
	}
	g_list_free(sdp->attributes);
	sdp->attributes = NULL;
	temp = sdp->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		janus_sdp_mline_destroy(m);
		temp = temp->next;
	}
	g_list_free(sdp->m_lines);
	sdp->m_lines = NULL;
	g_free(sdp);
}

static void janus_sdp_mline_free(const janus_refcount *mline_ref) {
	janus_sdp_mline *mline = janus_refcount_containerof(mline_ref, janus_sdp_mline, ref);
	/* This SDP m-line instance can be destroyed, free all the resources */
	g_free(mline->type_str);
	g_free(mline->proto);
	g_free(mline->c_addr);
	g_free(mline->b_name);
	g_list_free_full(mline->fmts, (GDestroyNotify)g_free);
	mline->fmts = NULL;
	g_list_free(mline->ptypes);
	mline->ptypes = NULL;
	GList *temp = mline->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		janus_sdp_attribute_destroy(a);
		temp = temp->next;
	}
	g_list_free(mline->attributes);
	g_free(mline);
}

static void janus_sdp_attribute_free(const janus_refcount *attr_ref) {
	janus_sdp_attribute *attr = janus_refcount_containerof(attr_ref, janus_sdp_attribute, ref);
	/* This SDP attribute instance can be destroyed, free all the resources */
	g_free(attr->name);
	g_free(attr->value);
	g_free(attr);
}


/* SDP and m-lines/attributes code */
janus_sdp_mline *janus_sdp_mline_create(janus_sdp_mtype type, guint16 port, const char *proto, janus_sdp_mdirection direction) {
	janus_sdp_mline *m = g_malloc0(sizeof(janus_sdp_mline));
	g_atomic_int_set(&m->destroyed, 0);
	janus_refcount_init(&m->ref, janus_sdp_mline_free);
	m->type = type;
	const char *type_str = janus_sdp_mtype_str(type);
	if(type_str == NULL) {
		JANUS_LOG(LOG_WARN, "Unknown media type, type_str will have to be set manually\n");
	} else {
		m->type_str = g_strdup(type_str);
	}
	m->port = port;
	m->proto = proto ? g_strdup(proto) : NULL;
	m->direction = direction;
	return m;
}

janus_sdp_mline *janus_sdp_mline_find(janus_sdp *sdp, janus_sdp_mtype type) {
	if(sdp == NULL)
		return NULL;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(m->type == type)
			return m;
		ml = ml->next;
	}
	return NULL;
}

janus_sdp_mline *janus_sdp_mline_find_by_index(janus_sdp *sdp, int index) {
	if(sdp == NULL || index < 0)
		return NULL;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(m->index == index)
			return m;
		ml = ml->next;
	}
	return NULL;
}

int janus_sdp_mline_remove(janus_sdp *sdp, janus_sdp_mtype type) {
	if(sdp == NULL)
		return -1;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(m->type == type) {
			/* Found! */
			sdp->m_lines = g_list_remove(sdp->m_lines, m);
			janus_sdp_mline_destroy(m);
			return 0;
		}
		ml = ml->next;
	}
	/* If we got here, we couldn't the m-line */
	return -2;
}

janus_sdp_attribute *janus_sdp_attribute_create(const char *name, const char *value, ...) {
	if(!name)
		return NULL;
	janus_sdp_attribute *a = g_malloc(sizeof(janus_sdp_attribute));
	g_atomic_int_set(&a->destroyed, 0);
	janus_refcount_init(&a->ref, janus_sdp_attribute_free);
	a->name = g_strdup(name);
	a->direction = JANUS_SDP_DEFAULT;
	a->value = NULL;
	if(value) {
		char buffer[2048];
		va_list ap;
		va_start(ap, value);
		g_vsnprintf(buffer, sizeof(buffer), value, ap);
		va_end(ap);
		a->value = g_strdup(buffer);
	}
	return a;
}

int janus_sdp_attribute_add_to_mline(janus_sdp_mline *mline, janus_sdp_attribute *attr) {
	if(!mline || !attr)
		return -1;
	mline->attributes = g_list_append(mline->attributes, attr);
	return 0;
}

janus_sdp_mtype janus_sdp_parse_mtype(const char *type) {
	if(type == NULL)
		return JANUS_SDP_OTHER;
	if(!strcasecmp(type, "audio"))
		return JANUS_SDP_AUDIO;
	if(!strcasecmp(type, "video"))
		return JANUS_SDP_VIDEO;
	if(!strcasecmp(type, "application"))
		return JANUS_SDP_APPLICATION;
	return JANUS_SDP_OTHER;
}

const char *janus_sdp_mtype_str(janus_sdp_mtype type) {
	switch(type) {
		case JANUS_SDP_AUDIO:
			return "audio";
		case JANUS_SDP_VIDEO:
			return "video";
		case JANUS_SDP_APPLICATION:
			return "application";
		case JANUS_SDP_OTHER:
		default:
			break;
	}
	return NULL;
}

janus_sdp_mdirection janus_sdp_parse_mdirection(const char *direction) {
	if(direction == NULL)
		return JANUS_SDP_INVALID;
	if(!strcasecmp(direction, "sendrecv"))
		return JANUS_SDP_SENDRECV;
	if(!strcasecmp(direction, "sendonly"))
		return JANUS_SDP_SENDONLY;
	if(!strcasecmp(direction, "recvonly"))
		return JANUS_SDP_RECVONLY;
	if(!strcasecmp(direction, "inactive"))
		return JANUS_SDP_INACTIVE;
	return JANUS_SDP_INVALID;
}

const char *janus_sdp_mdirection_str(janus_sdp_mdirection direction) {
	switch(direction) {
		case JANUS_SDP_DEFAULT:
		case JANUS_SDP_SENDRECV:
			return "sendrecv";
		case JANUS_SDP_SENDONLY:
			return "sendonly";
		case JANUS_SDP_RECVONLY:
			return "recvonly";
		case JANUS_SDP_INACTIVE:
			return "inactive";
		case JANUS_SDP_INVALID:
		default:
			break;
	}
	return NULL;
}

const char *janus_sdp_oa_type_str(janus_sdp_oa_type type) {
	switch(type) {
		case JANUS_SDP_OA_MLINE:
			return "JANUS_SDP_OA_MLINE";
		case JANUS_SDP_OA_ENABLED:
			return "JANUS_SDP_OA_ENABLED";
		case JANUS_SDP_OA_MID:
			return "JANUS_SDP_OA_MID";
		case JANUS_SDP_OA_MSID:
			return "JANUS_SDP_OA_MSID";
		case JANUS_SDP_OA_DIRECTION:
			return "JANUS_SDP_OA_DIRECTION";
		case JANUS_SDP_OA_CODEC:
			return "JANUS_SDP_OA_CODEC";
		case JANUS_SDP_OA_EXTENSION:
			return "JANUS_SDP_OA_EXTENSION";
		case JANUS_SDP_OA_EXTENSIONS:
			return "JANUS_SDP_OA_EXTENSIONS";
		case JANUS_SDP_OA_ACCEPT_EXTMAP:
			return "JANUS_SDP_OA_ACCEPT_EXTMAP";
		case JANUS_SDP_OA_PT:
			return "JANUS_SDP_OA_PT";
		case JANUS_SDP_OA_FMTP:
			return "JANUS_SDP_OA_FMTP";
		case JANUS_SDP_OA_AUDIO_DTMF:
			return "JANUS_SDP_OA_AUDIO_DTMF";
		case JANUS_SDP_OA_VP9_PROFILE:
			return "JANUS_SDP_OA_VP9_PROFILE";
		case JANUS_SDP_OA_H264_PROFILE:
			return "JANUS_SDP_OA_H264_PROFILE";
		case JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS:
			return "JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS";
		case JANUS_SDP_OA_DATA_LEGACY:
			return "JANUS_SDP_OA_DATA_LEGACY";
		case JANUS_SDP_OA_DONE:
			return "JANUS_SDP_OA_DONE";
		default:
			break;
	}
	return NULL;
}

janus_sdp *janus_sdp_parse(const char *sdp, char *error, size_t errlen) {
	if(!sdp)
		return NULL;
	if(strstr(sdp, "v=") != sdp) {
		if(error)
			g_snprintf(error, errlen, "Invalid SDP (doesn't start with v=)");
		return NULL;
	}
	janus_sdp *imported = g_malloc0(sizeof(janus_sdp));
	g_atomic_int_set(&imported->destroyed, 0);
	janus_refcount_init(&imported->ref, janus_sdp_free);
	imported->o_ipv4 = TRUE;
	imported->c_ipv4 = TRUE;

	gboolean success = TRUE;
	janus_sdp_mline *mline = NULL;
	int mlines = 0;
	char *line = NULL, *cr = NULL, *rest = NULL;
	char *sdp_copy = g_strdup(sdp);
	gboolean first = TRUE, mline_ended = FALSE;
	/* When a m-line has been detected we re-use the previous SDP line */
	while(success && (mline_ended || (line = strtok_r(!first ? NULL: sdp_copy, "\n", &rest)) != NULL)) {
		first = FALSE;
		mline_ended = FALSE;
		cr = strchr(line, '\r');
		if(cr != NULL)
			*cr = '\0';
		if(*line == '\0') {
			if(cr != NULL)
				*cr = '\r';
			continue;
		}
		if(strnlen(line, 3) < 3) {
			if(error)
				g_snprintf(error, errlen, "Invalid line (%zu bytes): %s", strlen(line), line);
			success = FALSE;
			break;
		}
		if(*(line+1) != '=') {
			if(error)
				g_snprintf(error, errlen, "Invalid line (2nd char is not '='): %s", line);
			success = FALSE;
			break;
		}
		char c = *line;
		if(mline == NULL) {
			/* Global stuff */
			switch(c) {
				case 'v': {
					if(sscanf(line, "v=%d", &imported->version) != 1) {
						if(error)
							g_snprintf(error, errlen, "Invalid v= line: %s", line);
						success = FALSE;
						break;
					}
					break;
				}
				case 'o': {
					if(imported->o_name || imported->o_addr) {
						if(error)
							g_snprintf(error, errlen, "Multiple o= lines: %s", line);
						success = FALSE;
						break;
					}
					char name[256], addrtype[6], addr[256];
					if(sscanf(line, "o=%255s %"SCNu64" %"SCNu64" IN %5s %255s",
							name, &imported->o_sessid, &imported->o_version, addrtype, addr) != 5) {
						if(error)
							g_snprintf(error, errlen, "Invalid o= line: %s", line);
						success = FALSE;
						break;
					}
					if(!strcasecmp(addrtype, "IP4"))
						imported->o_ipv4 = TRUE;
					else if(!strcasecmp(addrtype, "IP6"))
						imported->o_ipv4 = FALSE;
					else {
						if(error)
							g_snprintf(error, errlen, "Invalid o= line (unsupported protocol %s): %s", addrtype, line);
						success = FALSE;
						break;
					}
					imported->o_name = g_strdup(name);
					imported->o_addr = g_strdup(addr);
					break;
				}
				case 's': {
					if(imported->s_name) {
						if(error)
							g_snprintf(error, errlen, "Multiple s= lines: %s", line);
						success = FALSE;
						break;
					}
					imported->s_name = g_strdup(line+2);
					break;
				}
				case 't': {
					if(sscanf(line, "t=%"SCNu64" %"SCNu64, &imported->t_start, &imported->t_stop) != 2) {
						if(error)
							g_snprintf(error, errlen, "Invalid t= line: %s", line);
						success = FALSE;
						break;
					}
					break;
				}
				case 'c': {
					if(imported->c_addr) {
						if(error)
							g_snprintf(error, errlen, "Multiple global c= lines: %s", line);
						success = FALSE;
						break;
					}
					char addrtype[6], addr[256];
					if(sscanf(line, "c=IN %5s %255s", addrtype, addr) != 2) {
						if(error)
							g_snprintf(error, errlen, "Invalid c= line: %s", line);
						success = FALSE;
						break;
					}
					if(!strcasecmp(addrtype, "IP4"))
						imported->c_ipv4 = TRUE;
					else if(!strcasecmp(addrtype, "IP6"))
						imported->c_ipv4 = FALSE;
					else {
						if(error)
							g_snprintf(error, errlen, "Invalid c= line (unsupported protocol %s): %s", addrtype, line);
						success = FALSE;
						break;
					}
					imported->c_addr = g_strdup(addr);
					break;
				}
				case 'a': {
					janus_sdp_attribute *a = g_malloc0(sizeof(janus_sdp_attribute));
					janus_refcount_init(&a->ref, janus_sdp_attribute_free);
					line += 2;
					char *semicolon = strchr(line, ':');
					if(semicolon == NULL) {
						a->name = g_strdup(line);
						a->value = NULL;
					} else {
						if(*(semicolon+1) == '\0') {
							janus_sdp_attribute_destroy(a);
							if(error)
								g_snprintf(error, errlen, "Invalid a= line: %s", line);
							success = FALSE;
							break;
						}
						*semicolon = '\0';
						a->name = g_strdup(line);
						a->value = g_strdup(semicolon+1);
						a->direction = JANUS_SDP_DEFAULT;
						*semicolon = ':';
						if(strstr(line, "/sendonly"))
							a->direction = JANUS_SDP_SENDONLY;
						else if(strstr(line, "/recvonly"))
							a->direction = JANUS_SDP_RECVONLY;
						if(strstr(line, "/inactive"))
							a->direction = JANUS_SDP_INACTIVE;
					}
					imported->attributes = g_list_prepend(imported->attributes, a);
					break;
				}
				case 'm': {
					janus_sdp_mline *m = g_malloc0(sizeof(janus_sdp_mline));
					g_atomic_int_set(&m->destroyed, 0);
					janus_refcount_init(&m->ref, janus_sdp_mline_free);
					/* Start with media type, port and protocol */
					char type[32];
					char proto[64];
					if(strnlen(line, 200 + 1) > 200) {
						janus_sdp_mline_destroy(m);
						if(error)
							g_snprintf(error, errlen, "Invalid m= line (too long): %zu", strlen(line));
						success = FALSE;
						break;
					}
					if(sscanf(line, "m=%31s %"SCNu16" %63s %*s", type, &m->port, proto) != 3) {
						janus_sdp_mline_destroy(m);
						if(error)
							g_snprintf(error, errlen, "Invalid m= line: %s", line);
						success = FALSE;
						break;
					}
					m->index = mlines;
					mlines++;
					m->type = janus_sdp_parse_mtype(type);
					if(m->type == JANUS_SDP_OTHER) {
						janus_sdp_mline_destroy(m);
						if(error)
							g_snprintf(error, errlen, "Invalid m= line: %s", line);
						success = FALSE;
						break;
					}
					m->type_str = g_strdup(type);
					m->proto = g_strdup(proto);
					m->direction = JANUS_SDP_SENDRECV;
					m->c_ipv4 = TRUE;
					/* Now let's check the payload types/formats */
					gchar **mline_parts = g_strsplit(line+2, " ", -1);
					if(!mline_parts && (m->port > 0 || m->type == JANUS_SDP_APPLICATION)) {
						janus_sdp_mline_destroy(m);
						if(error)
							g_snprintf(error, errlen, "Invalid m= line (no payload types/formats): %s", line);
						success = FALSE;
						break;
					} else {
						int mindex = 0;
						while(mline_parts[mindex]) {
							if(mindex < 3) {
								/* We've parsed these before */
								mindex++;
								continue;
							}
							/* Add string fmt */
							m->fmts = g_list_prepend(m->fmts, g_strdup(mline_parts[mindex]));
							/* Add numeric payload type */
							int ptype = atoi(mline_parts[mindex]);
							if(ptype < 0) {
								JANUS_LOG(LOG_ERR, "Invalid payload type (%s)\n", mline_parts[mindex]);
							} else {
								m->ptypes = g_list_prepend(m->ptypes, GINT_TO_POINTER(ptype));
							}
							mindex++;
						}
						g_strfreev(mline_parts);
						if(m->fmts == NULL || m->ptypes == NULL) {
							janus_sdp_mline_destroy(m);
							if(error)
								g_snprintf(error, errlen, "Invalid m= line (no payload types/formats): %s", line);
							success = FALSE;
							break;
						}
						m->fmts = g_list_reverse(m->fmts);
						m->ptypes = g_list_reverse(m->ptypes);
					}
					/* Append to the list of m-lines */
					imported->m_lines = g_list_prepend(imported->m_lines, m);
					/* From now on, we parse this m-line */
					mline = m;
					break;
				}
				default:
					JANUS_LOG(LOG_WARN, "Ignoring '%c' property\n", c);
					break;
			}
		} else {
			/* m-line stuff */
			switch(c) {
				case 'c': {
					if(mline->c_addr) {
						if(error)
							g_snprintf(error, errlen, "Multiple m-line c= lines: %s", line);
						success = FALSE;
						break;
					}
					char addrtype[6], addr[256];
					if(sscanf(line, "c=IN %5s %255s", addrtype, addr) != 2) {
						if(error)
							g_snprintf(error, errlen, "Invalid c= line: %s", line);
						success = FALSE;
						break;
					}
					if(!strcasecmp(addrtype, "IP4"))
						mline->c_ipv4 = TRUE;
					else if(!strcasecmp(addrtype, "IP6"))
						mline->c_ipv4 = FALSE;
					else {
						if(error)
							g_snprintf(error, errlen, "Invalid c= line (unsupported protocol %s): %s", addrtype, line);
						success = FALSE;
						break;
					}
					mline->c_addr = g_strdup(addr);
					break;
				}
				case 'b': {
					if(mline->b_name) {
						JANUS_LOG(LOG_WARN, "Ignoring extra m-line b= line: %s\n", line);
						if(cr != NULL)
							*cr = '\r';
						continue;
					}
					line += 2;
					char *semicolon = strchr(line, ':');
					if(semicolon == NULL || (*(semicolon+1) == '\0')) {
						if(error)
							g_snprintf(error, errlen, "Invalid b= line: %s", line);
						success = FALSE;
						break;
					}
					*semicolon = '\0';
					if(strcmp(line, "AS") && strcmp(line, "TIAS")) {
						/* We only support b=AS and b=TIAS, skip */
						break;
					}
					mline->b_name = g_strdup(line);
					mline->b_value = atol(semicolon+1);
					*semicolon = ':';
					break;
				}
				case 'a': {
					janus_sdp_attribute *a = g_malloc0(sizeof(janus_sdp_attribute));
					janus_refcount_init(&a->ref, janus_sdp_attribute_free);
					line += 2;
					char *semicolon = strchr(line, ':');
					if(semicolon == NULL) {
						/* Is this a media direction attribute? */
						janus_sdp_mdirection direction = janus_sdp_parse_mdirection(line);
						if(direction != JANUS_SDP_INVALID) {
							janus_sdp_attribute_destroy(a);
							mline->direction = direction;
							break;
						}
						a->name = g_strdup(line);
						a->value = NULL;
					} else {
						if(*(semicolon+1) == '\0') {
							janus_sdp_attribute_destroy(a);
							if(error)
								g_snprintf(error, errlen, "Invalid a= line: %s", line);
							success = FALSE;
							break;
						}
						*semicolon = '\0';
						a->name = g_strdup(line);
						a->value = g_strdup(semicolon+1);
						a->direction = JANUS_SDP_DEFAULT;
						*semicolon = ':';
						if(strstr(line, "/sendonly"))
							a->direction = JANUS_SDP_SENDONLY;
						else if(strstr(line, "/recvonly"))
							a->direction = JANUS_SDP_RECVONLY;
						if(strstr(line, "/inactive"))
							a->direction = JANUS_SDP_INACTIVE;
					}
					mline->attributes = g_list_prepend(mline->attributes, a);
					break;
				}
				case 'm': {
					/* Current m-line ended, back to global parsing */
					if(mline && mline->attributes)
						mline->attributes = g_list_reverse(mline->attributes);
					mline = NULL;
					mline_ended = TRUE;
					continue;
				}
				default:
					JANUS_LOG(LOG_WARN, "Ignoring '%c' property (m-line)\n", c);
					break;
			}
		}
		if(cr != NULL)
			*cr = '\r';
	}
	if(cr != NULL)
		*cr = '\r';
	g_free(sdp_copy);
	/* FIXME Do a last check: is all the stuff that's supposed to be there available? */
	if(success && (imported->o_name == NULL || imported->o_addr == NULL || imported->s_name == NULL || imported->m_lines == NULL)) {
		success = FALSE;
		if(error)
			g_snprintf(error, errlen, "Missing mandatory lines (o=, s= or m=)");
	}
	/* If something wrong happened, free and return a failure */
	if(!success) {
		if(error)
			JANUS_LOG(LOG_ERR, "%s\n", error);
		janus_sdp_destroy(imported);
		imported = NULL;
	} else {
		/* Reverse lists for efficiency */
		if(mline && mline->attributes)
			mline->attributes = g_list_reverse(mline->attributes);
		if(imported->attributes)
			imported->attributes = g_list_reverse(imported->attributes);
		if(imported->m_lines)
			imported->m_lines = g_list_reverse(imported->m_lines);
	}
	return imported;
}

int janus_sdp_remove_payload_type(janus_sdp *sdp, int index, int pt) {
	if(!sdp || pt < 0)
		return -1;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(index != -1 && index != m->index) {
			ml = ml->next;
			continue;
		}
		/* Remove any reference from the m-line */
		m->ptypes = g_list_remove(m->ptypes, GINT_TO_POINTER(pt));
		/* Also remove all attributes that reference the same payload type */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->value && atoi(a->value) == pt) {
				m->attributes = g_list_remove(m->attributes, a);
				ma = m->attributes;
				janus_sdp_attribute_destroy(a);
				continue;
			}
			ma = ma->next;
		}
		if(index != -1)
			break;
		ml = ml->next;
	}
	return 0;
}

int janus_sdp_get_codec_pt(janus_sdp *sdp, int index, const char *codec) {
	return janus_sdp_get_codec_pt_full(sdp, index, codec, NULL);
}

int janus_sdp_get_codec_pt_full(janus_sdp *sdp, int index, const char *codec, const char *profile) {
	if(sdp == NULL || codec == NULL)
		return -1;
	/* Check the format string (note that we only parse what browsers can negotiate) */
	gboolean video = FALSE, vp9 = FALSE, h264 = FALSE;
	const char *format = NULL, *format2 = NULL;
	if(!strcasecmp(codec, "opus")) {
		format = "opus/48000/2";
		format2 = "OPUS/48000/2";
	} else if(!strcasecmp(codec, "multiopus")) {
		/* FIXME We're hardcoding to 6 channels, for now */
		format = "multiopus/48000/6";
		format2 = "MULTIOPUS/48000/6";
	} else if(!strcasecmp(codec, "pcmu")) {
		/* We know the payload type is 0: we just need to make sure it's there */
		format = "pcmu/8000";
		format2 = "PCMU/8000";
	} else if(!strcasecmp(codec, "pcma")) {
		/* We know the payload type is 8: we just need to make sure it's there */
		format = "pcma/8000";
		format2 = "PCMA/8000";
	} else if(!strcasecmp(codec, "g722")) {
		/* We know the payload type is 9: we just need to make sure it's there */
		format = "g722/8000";
		format2 = "G722/8000";
	} else if(!strcasecmp(codec, "isac16")) {
		format = "isac/16000";
		format2 = "ISAC/16000";
	} else if(!strcasecmp(codec, "isac32")) {
		format = "isac/32000";
		format2 = "ISAC/32000";
	} else if(!strcasecmp(codec, "l16-48")) {
		format = "l16/48000";
		format2 = "L16/48000";
	} else if(!strcasecmp(codec, "l16")) {
		format = "l16/16000";
		format2 = "L16/16000";
	} else if(!strcasecmp(codec, "dtmf")) {
		format = "telephone-event/8000";
		format2 = "TELEPHONE-EVENT/8000";
	} else if(!strcasecmp(codec, "vp8")) {
		video = TRUE;
		format = "vp8/90000";
		format2 = "VP8/90000";
	} else if(!strcasecmp(codec, "vp9")) {
		video = TRUE;
		vp9 = TRUE;		/* We may need to filter on profiles */
		format = "vp9/90000";
		format2 = "VP9/90000";
	} else if(!strcasecmp(codec, "h264")) {
		video = TRUE;
		h264 = TRUE;	/* We may need to filter on profiles */
		format = "h264/90000";
		format2 = "H264/90000";
	} else if(!strcasecmp(codec, "av1")) {
		video = TRUE;
		format = "av1/90000";
		format2 = "AV1/90000";
	} else if(!strcasecmp(codec, "h265")) {
		video = TRUE;
		format = "h265/90000";
		format2 = "H265/90000";
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
		return -1;
	}
	/* Check all m->lines */
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if((!video && m->type != JANUS_SDP_AUDIO) || (video && m->type != JANUS_SDP_VIDEO)) {
			ml = ml->next;
			continue;
		}
		if(index != -1 && index != m->index) {
			ml = ml->next;
			continue;
		}
		/* Look in all rtpmap attributes first */
		GList *ma = m->attributes;
		int pt = -1;
		GList *pts = NULL;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "rtpmap")) {
				pt = atoi(a->value);
				if(pt < 0) {
					JANUS_LOG(LOG_ERR, "Invalid payload type (%s)\n", a->value);
				} else if(strstr(a->value, format) || strstr(a->value, format2)) {
					if(profile != NULL && (vp9 || h264)) {
						/* Let's keep track of this payload type */
						pts = g_list_append(pts, GINT_TO_POINTER(pt));
					} else {
						/* Payload type for codec found */
						g_list_free(pts);
						return pt;
					}
				}
			}
			ma = ma->next;
		}
		if(profile != NULL) {
			/* Now look for the profile in the fmtp attributes */
			ma = m->attributes;
			while(ma) {
				janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
				if(profile != NULL && a->name != NULL && a->value != NULL && !strcasecmp(a->name, "fmtp")) {
					/* Does this match the payload types we're looking for? */
					pt = atoi(a->value);
					if(g_list_find(pts, GINT_TO_POINTER(pt)) == NULL) {
						/* Not what we're looking for */
						ma = ma->next;
						continue;
					}
					if(vp9) {
						char profile_id[20];
						g_snprintf(profile_id, sizeof(profile_id), "profile-id=%s", profile);
						if(strstr(a->value, profile_id) != NULL) {
							/* Found */
							JANUS_LOG(LOG_VERB, "VP9 profile %s found --> %d\n", profile, pt);
							g_list_free(pts);
							return pt;
						}
					} else if(h264 && strstr(a->value, "packetization-mode=0") == NULL) {
						/* We only support packetization-mode=1, no matter the profile */
						char profile_level_id[30];
						char *profile_lower = g_ascii_strdown(profile, -1);
						g_snprintf(profile_level_id, sizeof(profile_level_id), "profile-level-id=%s", profile_lower);
						g_free(profile_lower);
						if(strstr(a->value, profile_level_id) != NULL) {
							/* Found */
							JANUS_LOG(LOG_VERB, "H.264 profile %s found --> %d\n", profile, pt);
							g_list_free(pts);
							return pt;
						}
						/* Not found, try converting the profile to upper case */
						char *profile_upper = g_ascii_strup(profile, -1);
						g_snprintf(profile_level_id, sizeof(profile_level_id), "profile-level-id=%s", profile_upper);
						g_free(profile_upper);
						if(strstr(a->value, profile_level_id) != NULL) {
							/* Found */
							JANUS_LOG(LOG_VERB, "H.264 profile %s found --> %d\n", profile, pt);
							g_list_free(pts);
							return pt;
						}
					}
				}
				ma = ma->next;
			}
		}
		g_list_free(pts);
		if(index != -1)
			break;
		ml = ml->next;
	}
	return -1;
}

const char *janus_sdp_get_codec_name(janus_sdp *sdp, int index, int pt) {
	if(sdp == NULL || pt < 0)
		return NULL;
	if(pt == 0)
		return "pcmu";
	if(pt == 8)
		return "pcma";
	if(pt == 9)
		return "g722";
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(index != -1 && index != m->index) {
			ml = ml->next;
			continue;
		}
		/* Look in all rtpmap attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "rtpmap")) {
				int a_pt = atoi(a->value);
				if(a_pt == pt) {
					/* Found! */
					if(strstr(a->value, "vp8") || strstr(a->value, "VP8"))
						return "vp8";
					if(strstr(a->value, "vp9") || strstr(a->value, "VP9"))
						return "vp9";
					if(strstr(a->value, "h264") || strstr(a->value, "H264"))
						return "h264";
					if(strstr(a->value, "av1") || strstr(a->value, "AV1"))
						return "av1";
					if(strstr(a->value, "h265") || strstr(a->value, "H265"))
						return "h265";
					if(strstr(a->value, "multiopus") || strstr(a->value, "MULTIOPUS"))
						return "multiopus";
					if(strstr(a->value, "opus") || strstr(a->value, "OPUS"))
						return "opus";
					if(strstr(a->value, "pcmu") || strstr(a->value, "PCMU"))
						return "pcmu";
					if(strstr(a->value, "pcma") || strstr(a->value, "PCMA"))
						return "pcma";
					if(strstr(a->value, "g722") || strstr(a->value, "G722"))
						return "g722";
					if(strstr(a->value, "isac/16") || strstr(a->value, "ISAC/16"))
						return "isac16";
					if(strstr(a->value, "isac/32") || strstr(a->value, "ISAC/32"))
						return "isac32";
					if(strstr(a->value, "l16/48") || strstr(a->value, "L16/48"))
						return "l16-48";
					if(strstr(a->value, "l16/16") || strstr(a->value, "L16/16"))
						return "l16";
					if(strstr(a->value, "telephone-event/8000") || strstr(a->value, "telephone-event/8000"))
						return "dtmf";
					/* RED is not really a codec, but we need to detect it anyway */
					if(strstr(a->value, "red") || strstr(a->value, "RED"))
						return "red";
					JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", a->value);
					return NULL;
				}
			}
			ma = ma->next;
		}
		if(index != -1)
			break;
		ml = ml->next;
	}
	return NULL;
}

const char *janus_sdp_get_rtpmap_codec(const char *rtpmap) {
	if(rtpmap == NULL)
		return NULL;
	const char *codec = NULL;
	char *rtpmap_val = g_ascii_strdown(rtpmap, -1);
	if(strstr(rtpmap_val, "opus/") == rtpmap_val)
		codec = "opus";
	else if(strstr(rtpmap_val, "multiopus/") == rtpmap_val)
		codec = "multiopus";
	else if(strstr(rtpmap_val, "pcmu/") == rtpmap_val)
		codec = "pcmu";
	else if(strstr(rtpmap_val, "pcma/") == rtpmap_val)
		codec = "pcma";
	else if(strstr(rtpmap_val, "g722/") == rtpmap_val)
		codec = "g722";
	else if(strstr(rtpmap_val, "isac/16") == rtpmap_val)
		codec = "isac16";
	else if(strstr(rtpmap_val, "isac/32") == rtpmap_val)
		codec = "isac32";
	else if(strstr(rtpmap_val, "l16/48") == rtpmap_val)
		codec = "l16-48";
	else if(strstr(rtpmap_val, "l16/16") == rtpmap_val)
		codec = "l16";
	else if(strstr(rtpmap_val, "telephone-event/") == rtpmap_val)
		codec = "dtmf";
	else if(strstr(rtpmap_val, "vp8/") == rtpmap_val)
		codec = "vp8";
	else if(strstr(rtpmap_val, "vp9/") == rtpmap_val)
		codec = "vp9";
	else if(strstr(rtpmap_val, "h264/") == rtpmap_val)
		codec = "h264";
	else if(strstr(rtpmap_val, "av1/") == rtpmap_val)
		codec = "av1";
	else if(strstr(rtpmap_val, "h265/") == rtpmap_val)
		codec = "h265";
	if(codec == NULL)
		JANUS_LOG(LOG_ERR, "Unsupported rtpmap '%s'\n", rtpmap);
	g_free(rtpmap_val);
	return codec;
}

const char *janus_sdp_get_codec_rtpmap(const char *codec) {
	if(codec == NULL)
		return NULL;
	if(!strcasecmp(codec, "opus"))
		return "opus/48000/2";
	if(!strcasecmp(codec, "multiopus"))
		/* FIXME We're hardcoding to 6 channels, for now */
		return "multiopus/48000/6";
	if(!strcasecmp(codec, "pcmu"))
		return "PCMU/8000";
	if(!strcasecmp(codec, "pcma"))
		return "PCMA/8000";
	if(!strcasecmp(codec, "g722"))
		return "G722/8000";
	if(!strcasecmp(codec, "isac16"))
		return "ISAC/16000";
	if(!strcasecmp(codec, "isac32"))
		return "ISAC/32000";
	if(!strcasecmp(codec, "l16-48"))
		return "L16/48000";
	if(!strcasecmp(codec, "l16"))
		return "L16/16000";
	if(!strcasecmp(codec, "dtmf"))
		return "telephone-event/8000";
	if(!strcasecmp(codec, "vp8"))
		return "VP8/90000";
	if(!strcasecmp(codec, "vp9"))
		return "VP9/90000";
	if(!strcasecmp(codec, "h264"))
		return "H264/90000";
	if(!strcasecmp(codec, "av1"))
		return "AV1/90000";
	if(!strcasecmp(codec, "h265"))
		return "H265/90000";
	JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
	return NULL;
}

const char *janus_sdp_get_fmtp(janus_sdp *sdp, int index, int pt) {
	if(sdp == NULL || pt < 0)
		return NULL;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(index != -1 && index != m->index) {
			ml = ml->next;
			continue;
		}
		/* Look in all fmtp attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "fmtp")) {
				int a_pt = atoi(a->value);
				if(a_pt == pt) {
					/* Found! */
					char needle[10];
					g_snprintf(needle, sizeof(needle), "%d ", pt);
					if(strstr(a->value, needle) == a->value)
						return a->value + strlen(needle);
				}
			}
			ma = ma->next;
		}
		if(index != -1)
			break;
		ml = ml->next;
	}
	return NULL;
}

char *janus_sdp_get_video_profile(janus_videocodec codec, const char *fmtp) {
	if(fmtp == NULL)
		return NULL;
	const char *needle = NULL;
	if(codec == JANUS_VIDEOCODEC_H264) {
		needle = "profile-level-id=";
	} else if(codec == JANUS_VIDEOCODEC_VP9) {
		needle = "profile-id=";
	} else {
		return NULL;
	}
	gchar **list = g_strsplit(fmtp, ";", -1);
	int i=0;
	gchar *index = list[0];
	char *profile = NULL;
	while(index != NULL) {
		if(strstr(index, needle) != NULL) {
			profile = index + strlen(needle);
			if(strlen(profile) > 0)
				profile = g_strdup(profile);
			else
				profile = NULL;
			break;
		}
		i++;
		index = list[i];
	}
	g_clear_pointer(&list, g_strfreev);
	return profile;
}

int janus_sdp_get_opusred_pt(janus_sdp *sdp, int index) {
	if(sdp == NULL)
		return -1;
	/* Check all m->lines */
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(m->type != JANUS_SDP_AUDIO) {
			ml = ml->next;
			continue;
		}
		if(index != -1 && index != m->index) {
			ml = ml->next;
			continue;
		}
		/* Look in all rtpmap attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "rtpmap")) {
				int pt = atoi(a->value);
				if(strstr(a->value, "red/48000/2"))
					return pt;
			}
			ma = ma->next;
		}
		if(index != -1)
			break;
		ml = ml->next;
	}
	return -1;
}

char *janus_sdp_write(janus_sdp *imported) {
	if(!imported)
		return NULL;
	janus_refcount_increase(&imported->ref);
	char *sdp = g_malloc(2560), mline[8192], buffer[2048];
	*sdp = '\0';
	size_t sdplen = 2560, mlen = sizeof(mline), offset = 0, moffset = 0;
	/* v= */
	g_snprintf(buffer, sizeof(buffer), "v=%d\r\n", imported->version);
	janus_strlcat_fast(sdp, buffer, sdplen, &offset);
	/* o= */
	g_snprintf(buffer, sizeof(buffer), "o=%s %"SCNu64" %"SCNu64" IN %s %s\r\n",
		imported->o_name, imported->o_sessid, imported->o_version,
		imported->o_ipv4 ? "IP4" : "IP6", imported->o_addr);
	janus_strlcat_fast(sdp, buffer, sdplen, &offset);
	/* s= */
	g_snprintf(buffer, sizeof(buffer), "s=%s\r\n", imported->s_name);
	janus_strlcat_fast(sdp, buffer, sdplen, &offset);
	/* t= */
	g_snprintf(buffer, sizeof(buffer), "t=%"SCNu64" %"SCNu64"\r\n", imported->t_start, imported->t_stop);
	janus_strlcat_fast(sdp, buffer, sdplen, &offset);
	/* c= */
	if(imported->c_addr != NULL) {
		if(imported->c_ipv4 && imported->c_addr && strstr(imported->c_addr, ":"))
			imported->c_ipv4 = FALSE;
		g_snprintf(buffer, sizeof(buffer), "c=IN %s %s\r\n",
			imported->c_ipv4 ? "IP4" : "IP6", imported->c_addr);
		janus_strlcat_fast(sdp, buffer, sdplen, &offset);
	}
	/* a= */
	GList *temp = imported->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		if(a->value != NULL) {
			g_snprintf(buffer, sizeof(buffer), "a=%s:%s\r\n", a->name, a->value);
		} else {
			g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", a->name);
		}
		janus_strlcat_fast(sdp, buffer, sdplen, &offset);
		temp = temp->next;
	}
	/* m= */
	temp = imported->m_lines;
	while(temp) {
		mline[0] = '\0';
		moffset = 0;
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		g_snprintf(buffer, sizeof(buffer), "m=%s %d %s", m->type_str, m->port, m->proto);
		janus_strlcat_fast(mline, buffer, mlen, &moffset);
		if(m->port == 0 && m->type != JANUS_SDP_APPLICATION) {
			/* Remove all payload types/formats if we're rejecting the media */
			g_list_free_full(m->fmts, (GDestroyNotify)g_free);
			m->fmts = NULL;
			g_list_free(m->ptypes);
			m->ptypes = NULL;
			m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(0));
			janus_strlcat_fast(mline, " 0", mlen, &moffset);
		} else {
			if(m->proto != NULL && strstr(m->proto, "RTP") != NULL) {
				/* RTP profile, use payload types */
				GList *ptypes = m->ptypes;
				while(ptypes) {
					g_snprintf(buffer, sizeof(buffer), " %d", GPOINTER_TO_INT(ptypes->data));
					janus_strlcat_fast(mline, buffer, mlen, &moffset);
					ptypes = ptypes->next;
				}
			} else {
				/* Something else, use formats */
				GList *fmts = m->fmts;
				while(fmts) {
					g_snprintf(buffer, sizeof(buffer), " %s", (char *)(fmts->data));
					janus_strlcat_fast(mline, buffer, mlen, &moffset);
					fmts = fmts->next;
				}
			}
		}
		janus_strlcat_fast(mline, "\r\n", mlen, &moffset);
		/* c= */
		if(m->c_addr != NULL) {
			g_snprintf(buffer, sizeof(buffer), "c=IN %s %s\r\n",
				m->c_ipv4 ? "IP4" : "IP6", m->c_addr);
			janus_strlcat_fast(mline, buffer, mlen, &moffset);
		}
		if(m->port > 0) {
			/* b= */
			if(m->b_name != NULL) {
				g_snprintf(buffer, sizeof(buffer), "b=%s:%"SCNu32"\r\n", m->b_name, m->b_value);
				janus_strlcat_fast(mline, buffer, mlen, &moffset);
			}
		}
		/* a= (note that we don't format the direction if it's JANUS_SDP_DEFAULT) */
		const char *direction = m->direction != JANUS_SDP_DEFAULT ? janus_sdp_mdirection_str(m->direction) : NULL;
		if(direction != NULL) {
			g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", direction);
			janus_strlcat_fast(mline, buffer, mlen, &moffset);
		}
		GList *temp2 = m->attributes;
		while(temp2) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)temp2->data;
			if(m->port == 0 && strcasecmp(a->name, "mid")) {
				/* This media has been rejected or disabled: we only add the mid attribute, if available */
				temp2 = temp2->next;
				continue;
			}
			if(a->value != NULL) {
				g_snprintf(buffer, sizeof(buffer), "a=%s:%s\r\n", a->name, a->value);
			} else {
				g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", a->name);
			}
			janus_strlcat_fast(mline, buffer, mlen, &moffset);
			temp2 = temp2->next;
		}
		/* Append the generated m-line to the SDP */
		size_t cur_sdplen = strlen(sdp);
		size_t mlinelen = strlen(mline);
		if(cur_sdplen + mlinelen + 1 > sdplen) {
			/* Increase the SDP buffer first */
			if(sdplen < (mlinelen+1))
				sdplen = cur_sdplen + mlinelen + 1;
			else
				sdplen = sdplen*2;
			sdp = g_realloc(sdp, sdplen);
		}
		janus_strlcat_fast(sdp, mline, sdplen, &offset);
		/* Move on */
		temp = temp->next;
	}
	janus_refcount_decrease(&imported->ref);
	return sdp;
}

void janus_sdp_find_preferred_codec(janus_sdp *sdp, janus_sdp_mtype type, int index, const char **codec) {
	if(sdp == NULL)
		return;
	janus_refcount_increase(&sdp->ref);
	gboolean found = FALSE;
	GList *temp = sdp->m_lines;
	while(temp) {
		/* Which media are available? */
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		if(index != -1 && index != m->index) {
			temp = temp->next;
			continue;
		}
		if(m->type == type && m->port > 0 && m->direction != JANUS_SDP_INACTIVE) {
			uint i=0;
			for(i=0; i<(type == JANUS_SDP_AUDIO ? janus_audio_codecs : janus_video_codecs); i++) {
				if(janus_sdp_get_codec_pt(sdp, m->index,
						type == JANUS_SDP_AUDIO ? janus_preferred_audio_codecs[i] : janus_preferred_video_codecs[i]) > 0) {
					found = TRUE;
					if(codec)
						*codec = (type == JANUS_SDP_AUDIO ? janus_preferred_audio_codecs[i] : janus_preferred_video_codecs[i]);
					break;
				}
			}
		}
		if(found || index != -1)
			break;
		temp = temp->next;
	}
	janus_refcount_decrease(&sdp->ref);
}

void janus_sdp_find_first_codec(janus_sdp *sdp, janus_sdp_mtype type, int index, const char **codec) {
	if(sdp == NULL)
		return;
	janus_refcount_increase(&sdp->ref);
	gboolean found = FALSE;
	GList *temp = sdp->m_lines;
	while(temp) {
		/* Which media are available? */
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		if(index != -1 && index != m->index) {
			temp = temp->next;
			continue;
		}
		if(m->type == type && m->port > 0 && m->direction != JANUS_SDP_INACTIVE && m->ptypes) {
			int pt = GPOINTER_TO_INT(m->ptypes->data);
			const char *c = janus_sdp_get_codec_name(sdp, m->index, pt);
			if(c && !strcasecmp(c, "red")) {
				/* We're using RED, so check the second payload type for the actual codec */
				pt = m->ptypes->next ? GPOINTER_TO_INT(m->ptypes->next->data) : -1;
				c = janus_sdp_get_codec_name(sdp, m->index, pt);
			}
			c = janus_sdp_match_preferred_codec(m->type, (char *)c);
			if(c) {
				found = TRUE;
				if(codec)
					*codec = c;
			}
		}
		if(found || index != -1)
			break;
		temp = temp->next;
	}
	janus_refcount_decrease(&sdp->ref);
}

const char *janus_sdp_match_preferred_codec(janus_sdp_mtype type, char *codec) {
	if(codec == NULL)
		return NULL;
	if(type != JANUS_SDP_AUDIO && type != JANUS_SDP_VIDEO)
		return NULL;
	gboolean video = (type == JANUS_SDP_VIDEO);
	uint i=0;
	for(i=0; i<(video ? janus_video_codecs : janus_audio_codecs); i++) {
		if(!strcasecmp(codec, (video ? janus_preferred_video_codecs[i] : janus_preferred_audio_codecs[i]))) {
			/* Found! */
			return video ? janus_preferred_video_codecs[i] : janus_preferred_audio_codecs[i];
		}
	}
	return NULL;
}

janus_sdp *janus_sdp_new(const char *name, const char *address) {
	janus_sdp *sdp = g_malloc(sizeof(janus_sdp));
	g_atomic_int_set(&sdp->destroyed, 0);
	janus_refcount_init(&sdp->ref, janus_sdp_free);
	/* Fill in some predefined stuff */
	sdp->version = 0;
	sdp->o_name = g_strdup("-");
	sdp->o_sessid = janus_get_real_time();
	sdp->o_version = 1;
	sdp->o_ipv4 = TRUE;
	sdp->o_addr = g_strdup(address ? address : "127.0.0.1");
	sdp->s_name = g_strdup(name ? name : "Janus session");
	sdp->t_start = 0;
	sdp->t_stop = 0;
	sdp->c_ipv4 = TRUE;
	sdp->c_addr = g_strdup(address ? address : "127.0.0.1");
	sdp->attributes = NULL;
	sdp->m_lines = NULL;
	/* Done */
	return sdp;
}

static int janus_sdp_id_compare(gconstpointer a, gconstpointer b) {
	return GPOINTER_TO_INT(a) - GPOINTER_TO_INT(b);
}
janus_sdp *janus_sdp_generate_offer(const char *name, const char *address, ...) {
	/* This method has a variable list of arguments, telling us what we should offer */
	int property = -1;
	va_list args;
	va_start(args, address);

	/* Create a new janus_sdp object */
	janus_sdp *offer = janus_sdp_new(name, address);

	gboolean new_mline = FALSE, mline_enabled = FALSE;
	janus_sdp_mtype type = JANUS_SDP_OTHER;
	gboolean audio_dtmf = FALSE, video_rtcpfb = TRUE, data_legacy = FALSE;
	int pt = -1, opusred_pt = -1;
	const char *codec = NULL, *mid = NULL, *msid = NULL, *mstid = NULL,
		*fmtp = NULL, *vp9_profile = NULL, *h264_profile = NULL;
	janus_sdp_mdirection mdir = JANUS_SDP_DEFAULT;
	GHashTable *extmaps = NULL, *extids = NULL, *m_extids = NULL;

	while(property != JANUS_SDP_OA_DONE) {
		property = va_arg(args, int);
		if(!new_mline && property != JANUS_SDP_OA_MLINE && property != JANUS_SDP_OA_DONE) {
			/* The first attribute MUST be JANUS_SDP_OA_MLINE or JANUS_SDP_OA_DONE */
			JANUS_LOG(LOG_ERR, "First attribute is not JANUS_SDP_OA_MLINE or JANUS_SDP_OA_DONE\n");
			janus_sdp_destroy(offer);
			if(extmaps != NULL)
				g_hash_table_destroy(extmaps);
			if(extids != NULL)
				g_hash_table_destroy(extids);
			if(m_extids != NULL)
				g_hash_table_destroy(m_extids);
			va_end(args);
			return NULL;
		}
		if(property == JANUS_SDP_OA_MLINE || property == JANUS_SDP_OA_DONE) {
			/* A new m-line is starting or we're done, should we wrap the previous one? */
			new_mline = TRUE;
			if(mline_enabled) {
				/* Create a new m-line with the data collected so far */
				if(type == JANUS_SDP_AUDIO) {
					if(janus_sdp_generate_offer_mline(offer,
						JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
						JANUS_SDP_OA_MID, mid,
						JANUS_SDP_OA_MSID, msid, mstid,
						JANUS_SDP_OA_OPUSRED_PT, opusred_pt,
						JANUS_SDP_OA_CODEC, codec,
						JANUS_SDP_OA_DIRECTION, mdir,
						JANUS_SDP_OA_FMTP, fmtp,
						JANUS_SDP_OA_EXTENSIONS, m_extids,
						JANUS_SDP_OA_AUDIO_DTMF, audio_dtmf,
						JANUS_SDP_OA_DONE
					) < 0) {
						janus_sdp_destroy(offer);
						if(extmaps != NULL)
							g_hash_table_destroy(extmaps);
						if(extids != NULL)
							g_hash_table_destroy(extids);
						if(m_extids != NULL)
							g_hash_table_destroy(m_extids);
						va_end(args);
						return NULL;
					}
				} else if(type == JANUS_SDP_VIDEO) {
					if(janus_sdp_generate_offer_mline(offer,
						JANUS_SDP_OA_MLINE, JANUS_SDP_VIDEO,
						JANUS_SDP_OA_MID, mid,
						JANUS_SDP_OA_MSID, msid, mstid,
						JANUS_SDP_OA_PT, pt,
						JANUS_SDP_OA_CODEC, codec,
						JANUS_SDP_OA_DIRECTION, mdir,
						JANUS_SDP_OA_FMTP, fmtp,
						JANUS_SDP_OA_EXTENSIONS, m_extids,
						JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS, video_rtcpfb,
						JANUS_SDP_OA_VP9_PROFILE, vp9_profile,
						JANUS_SDP_OA_H264_PROFILE, h264_profile,
						JANUS_SDP_OA_DONE
					) < 0) {
						janus_sdp_destroy(offer);
						if(extmaps != NULL)
							g_hash_table_destroy(extmaps);
						if(extids != NULL)
							g_hash_table_destroy(extids);
						if(m_extids != NULL)
							g_hash_table_destroy(m_extids);
						va_end(args);
						return NULL;
					}
				} else if(type == JANUS_SDP_APPLICATION) {
					if(janus_sdp_generate_offer_mline(offer,
						JANUS_SDP_OA_MLINE, JANUS_SDP_APPLICATION,
						JANUS_SDP_OA_MID, mid,
						JANUS_SDP_OA_DATA_LEGACY, data_legacy,
						JANUS_SDP_OA_DONE
					) < 0) {
						janus_sdp_destroy(offer);
						if(extmaps != NULL)
							g_hash_table_destroy(extmaps);
						if(extids != NULL)
							g_hash_table_destroy(extids);
						if(m_extids != NULL)
							g_hash_table_destroy(m_extids);
						va_end(args);
						return NULL;
					}
				}
			}
			if(property != JANUS_SDP_OA_MLINE)
				continue;
			/* Now reset the properties */
			audio_dtmf = FALSE;
			video_rtcpfb = TRUE;
			data_legacy = FALSE;
			pt = -1;
			opusred_pt = -1;
			mid = NULL;
			msid = NULL;
			mstid = NULL;
			codec = NULL;
			fmtp = NULL;
			vp9_profile = NULL;
			h264_profile = NULL;
			if(m_extids != NULL)
				g_hash_table_destroy(m_extids);
			m_extids = NULL;
			mdir = JANUS_SDP_DEFAULT;
			mline_enabled = TRUE;
			/* The value of JANUS_SDP_OA_MLINE MUST be the media we want to add */
			type = va_arg(args, int);
			if(type == JANUS_SDP_AUDIO) {
				/* Audio, let's set some defaults */
				pt = 111;
				codec = "opus";
			} else if(type == JANUS_SDP_VIDEO) {
				/* Video, let's set some defaults */
				pt = 96;
				codec = "vp8";
			} else if(type == JANUS_SDP_APPLICATION) {
				/* Data */
			} else {
				/* Unsupported m-line type */
				JANUS_LOG(LOG_ERR, "Invalid m-line type\n");
				janus_sdp_destroy(offer);
				if(extmaps != NULL)
					g_hash_table_destroy(extmaps);
				if(extids != NULL)
					g_hash_table_destroy(extids);
				if(m_extids != NULL)
					g_hash_table_destroy(m_extids);
				va_end(args);
				return NULL;
			}
			/* Let's assume the m-line is enabled, by default */
			mline_enabled = TRUE;
		} else if(property == JANUS_SDP_OA_ENABLED) {
			mline_enabled = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_MID) {
			mid = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_MSID) {
			msid = va_arg(args, char *);
			mstid = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_DIRECTION) {
			mdir = va_arg(args, janus_sdp_mdirection);
		} else if(property == JANUS_SDP_OA_CODEC) {
			codec = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_PT) {
			pt = va_arg(args, int);
		} else if(property == JANUS_SDP_OA_OPUSRED_PT) {
			opusred_pt = va_arg(args, int);
		} else if(property == JANUS_SDP_OA_FMTP) {
			fmtp = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_VP9_PROFILE) {
			vp9_profile = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_H264_PROFILE) {
			h264_profile = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_AUDIO_DTMF) {
			audio_dtmf = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS) {
			video_rtcpfb = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_DATA_LEGACY) {
			data_legacy = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_EXTENSION) {
			char *extmap = va_arg(args, char *);
			int id = va_arg(args, int);
			if(extmap != NULL && id > 0 && id < 15) {
				if(extmaps == NULL)
					extmaps = g_hash_table_new(g_str_hash, g_str_equal);
				if(extids == NULL)
					extids = g_hash_table_new(NULL, NULL);
				/* Make sure the extmap and ID have not been added already */
				if(g_hash_table_lookup(extids, GINT_TO_POINTER(id)) == NULL &&
						g_hash_table_lookup(extmaps, extmap) == NULL) {
					g_hash_table_insert(extmaps, extmap, GINT_TO_POINTER(id));
					g_hash_table_insert(extids, GINT_TO_POINTER(id), extmap);
				}
				if(g_hash_table_lookup(extmaps, extmap) == GINT_TO_POINTER(id)) {
					if(m_extids == NULL)
						m_extids = g_hash_table_new(NULL, NULL);
					g_hash_table_insert(m_extids, GINT_TO_POINTER(id), extmap);
				}
			}
		} else {
			JANUS_LOG(LOG_WARN, "Unknown property %d for preparing SDP offer, ignoring...\n", property);
		}
	}
	if(extmaps != NULL)
		g_hash_table_destroy(extmaps);
	if(extids != NULL)
		g_hash_table_destroy(extids);

	/* Done */
	va_end(args);

	return offer;
}

int janus_sdp_generate_offer_mline(janus_sdp *offer, ...) {
	if(offer == NULL)
		return -1;

	/* This method has a variable list of arguments, telling us what we should offer */
	va_list args;
	va_start(args, offer);

	/* First of all, let's see what we should add */
	janus_sdp_mtype type = JANUS_SDP_OTHER;
	gboolean audio_dtmf = FALSE, video_rtcpfb = TRUE, data_legacy = FALSE;
	int pt = -1, opusred_pt = -1;
	const char *codec = NULL, *mid = NULL, *msid = NULL, *mstid = NULL,
		*rtpmap = NULL, *fmtp = NULL, *vp9_profile = NULL, *h264_profile = NULL;
	janus_sdp_mdirection mdir = JANUS_SDP_DEFAULT;
	GHashTable *extmaps = NULL, *extids = NULL;
	gboolean extids_allocated = FALSE;

	int property = va_arg(args, int);
	if(property != JANUS_SDP_OA_MLINE) {
		/* The first attribute MUST be JANUS_SDP_OA_MLINE */
		JANUS_LOG(LOG_ERR, "First attribute is not JANUS_SDP_OA_MLINE\n");
		va_end(args);
		return -2;
	}
	type = va_arg(args, int);
	if(type == JANUS_SDP_AUDIO) {
		/* Audio */
		pt = 111;
		codec = "opus";
	} else if(type == JANUS_SDP_VIDEO) {
		/* Video */
		pt = 96;
		codec = "vp8";
	} else if(type == JANUS_SDP_APPLICATION) {
		/* Data */
#ifndef HAVE_SCTP
		va_end(args);
		return -3;
#endif
	} else {
		/* Unsupported m-line type */
		JANUS_LOG(LOG_ERR, "Invalid m-line type\n");
		janus_sdp_destroy(offer);
		va_end(args);
		return -4;
	}

	/* Let's see what we should do with the media to add */
	property = va_arg(args, int);
	while(property != JANUS_SDP_OA_DONE) {
		if(property == JANUS_SDP_OA_DIRECTION) {
			mdir = va_arg(args, janus_sdp_mdirection);
		} else if(property == JANUS_SDP_OA_CODEC) {
			codec = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_MID) {
			mid = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_MSID) {
			msid = va_arg(args, char *);
			mstid = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_PT) {
			pt = va_arg(args, int);
		} else if(property == JANUS_SDP_OA_OPUSRED_PT) {
			opusred_pt = va_arg(args, int);
		} else if(property == JANUS_SDP_OA_FMTP) {
			fmtp = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_AUDIO_DTMF) {
			audio_dtmf = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS) {
			video_rtcpfb = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VP9_PROFILE) {
			vp9_profile = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_H264_PROFILE) {
			h264_profile = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_DATA_LEGACY) {
			data_legacy = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_EXTENSION) {
			if((extmaps != NULL || extids != NULL) && !extids_allocated) {
				JANUS_LOG(LOG_ERR, "Conflicting extensions settings (can't use both JANUS_SDP_OA_EXTENSION and JANUS_SDP_OA_EXTENSIONS)\n");
				if(extmaps != NULL)
					g_hash_table_destroy(extmaps);
				if(extids_allocated) {
					if(extids != NULL)
						g_hash_table_destroy(extids);
				}
				va_end(args);
				return -5;
			}
			char *extmap = va_arg(args, char *);
			int id = va_arg(args, int);
			if(extmap != NULL && id > 0 && id < 15) {
				if(extmaps == NULL)
					extmaps = g_hash_table_new(g_str_hash, g_str_equal);
				if(extids == NULL)
					extids = g_hash_table_new(NULL, NULL);
				extids_allocated = TRUE;
				/* Make sure the extmap and ID have not been added already */
				char *check_extmap = g_hash_table_lookup(extids, GINT_TO_POINTER(id));
				if(check_extmap != NULL) {
					JANUS_LOG(LOG_WARN, "Ignoring duplicate extension %d (already added: %s)\n", id, check_extmap);
				} else {
					if(g_hash_table_lookup(extmaps, extmap) != NULL) {
						JANUS_LOG(LOG_WARN, "Ignoring duplicate extension %s (already added: %d)\n",
							extmap, GPOINTER_TO_INT(g_hash_table_lookup(extmaps, extmap)));
					} else {
						g_hash_table_insert(extmaps, extmap, GINT_TO_POINTER(id));
						g_hash_table_insert(extids, GINT_TO_POINTER(id), extmap);
					}
				}
			}
		} else if(property == JANUS_SDP_OA_EXTENSIONS) {
			if(extmaps != NULL || extids != NULL) {
				JANUS_LOG(LOG_ERR, "Conflicting extensions settings (can't use both JANUS_SDP_OA_EXTENSION and JANUS_SDP_OA_EXTENSIONS)\n");
				if(extmaps != NULL)
					g_hash_table_destroy(extmaps);
				if(extids_allocated) {
					if(extids != NULL)
						g_hash_table_destroy(extids);
				}
				va_end(args);
				return -5;
			}
			extids = va_arg(args, GHashTable *);
			extids_allocated = FALSE;
		} else {
			JANUS_LOG(LOG_WARN, "Unknown property %d for preparing SDP answer, ignoring...\n", property);
		}
		property = va_arg(args, int);
	}
	/* Configure some defaults, if values weren't specified */
	if(type == JANUS_SDP_AUDIO) {
		if(codec == NULL)
			codec = "opus";
		rtpmap = janus_sdp_get_codec_rtpmap(codec);
		if(rtpmap == NULL) {
			JANUS_LOG(LOG_ERR, "Unsupported audio codec '%s', can't prepare an offer\n", codec);
			if(extmaps != NULL)
				g_hash_table_destroy(extmaps);
			if(extids_allocated) {
				if(extids != NULL)
					g_hash_table_destroy(extids);
			}
			va_end(args);
			return -3;
		}
	} else if(type == JANUS_SDP_VIDEO) {
		if(codec == NULL)
			codec = "vp8";
		rtpmap = janus_sdp_get_codec_rtpmap(codec);
		if(rtpmap == NULL) {
			JANUS_LOG(LOG_ERR, "Unsupported video codec '%s', can't prepare an offer\n", codec);
			if(extmaps != NULL)
				g_hash_table_destroy(extmaps);
			if(extids_allocated) {
				if(extids != NULL)
					g_hash_table_destroy(extids);
			}
			va_end(args);
			return -4;
		}
	}

	/* Create the m-line */
	const char *transport = "UDP/TLS/RTP/SAVPF";
	if(type == JANUS_SDP_APPLICATION)
		transport = (data_legacy ? "DTLS/SCTP" : "UDP/DTLS/SCTP");
	janus_sdp_mline *m = janus_sdp_mline_create(type, 9, transport, mdir);
	m->index = g_list_length(offer->m_lines);
	m->c_ipv4 = TRUE;
	m->c_addr = g_strdup(offer->c_addr);
	janus_sdp_attribute *a = NULL;
	/* Any mid we should set? */
	if(mid != NULL) {
		a = janus_sdp_attribute_create("mid", "%s", mid);
		m->attributes = g_list_append(m->attributes, a);
	}
	/* Any msid we should set? */
	if(type != JANUS_SDP_APPLICATION && msid != NULL && mstid != NULL) {
		a = janus_sdp_attribute_create("msid", "%s %s", msid, mstid);
		m->attributes = g_list_append(m->attributes, a);
	}
	if(type == JANUS_SDP_AUDIO || type == JANUS_SDP_VIDEO) {
		/* Add the selected codec */
		if(type == JANUS_SDP_AUDIO && opusred_pt > 0) {
			/* ... but add RED first */
			m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(opusred_pt));
			a = janus_sdp_attribute_create("rtpmap", "%d red/48000/2", opusred_pt);
			m->attributes = g_list_append(m->attributes, a);
		}
		m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(pt));
		a = janus_sdp_attribute_create("rtpmap", "%d %s", pt, rtpmap);
		m->attributes = g_list_append(m->attributes, a);
		if(type == JANUS_SDP_AUDIO) {
			/* Check if we need to add a payload type for DTMF tones (telephone-event/8000) */
			if(audio_dtmf) {
				/* We do */
				int dtmf_pt = 126;
				m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(dtmf_pt));
				a = janus_sdp_attribute_create("rtpmap", "%d %s", dtmf_pt, janus_sdp_get_codec_rtpmap("dtmf"));
				m->attributes = g_list_append(m->attributes, a);
			}
		}
		if(type == JANUS_SDP_VIDEO && video_rtcpfb) {
			/* Add rtcp-fb attributes */
			a = janus_sdp_attribute_create("rtcp-fb", "%d ccm fir", pt);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("rtcp-fb", "%d nack", pt);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("rtcp-fb", "%d nack pli", pt);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("rtcp-fb", "%d goog-remb", pt);
			m->attributes = g_list_append(m->attributes, a);
		}
		/* It is safe to add transport-wide rtcp feedback message here, won't be used unless the header extension is negotiated */
		a = janus_sdp_attribute_create("rtcp-fb", "%d transport-cc", pt);
		m->attributes = g_list_append(m->attributes, a);
		/* Check if we need to add extensions to the SDP */
		if(extids != NULL) {
			GList *ids = g_list_sort(g_hash_table_get_keys(extids), janus_sdp_id_compare), *iter = ids;
			while(iter) {
				char *extmap = g_hash_table_lookup(extids, iter->data);
				if(extmap != NULL) {
					a = janus_sdp_attribute_create("extmap",
						"%d %s", GPOINTER_TO_INT(iter->data), extmap);
					janus_sdp_attribute_add_to_mline(m, a);
				}
				iter = iter->next;
			}
			g_list_free(ids);
		}
		/* If RED is being offered, add an fmtp line for that */
		if(type == JANUS_SDP_AUDIO && opusred_pt > 0) {
			a = janus_sdp_attribute_create("fmtp", "%d %d/%d", opusred_pt, pt, pt);
			m->attributes = g_list_append(m->attributes, a);
		}
		/* Check if there's a custom fmtp line to add */
		if(type == JANUS_SDP_AUDIO && fmtp != NULL) {
			a = janus_sdp_attribute_create("fmtp", "%d %s", pt, fmtp);
			m->attributes = g_list_append(m->attributes, a);
		} else if(type == JANUS_SDP_VIDEO) {
			/* For video we can configure an fmtp in different ways */
			if(!strcasecmp(codec, "vp9") && vp9_profile) {
				/* Add a profile-id fmtp attribute */
				a = janus_sdp_attribute_create("fmtp", "%d profile-id=%s", pt, vp9_profile);
				m->attributes = g_list_append(m->attributes, a);
			} else if(!strcasecmp(codec, "h264") && h264_profile) {
				/* Add a profile-level-id fmtp attribute */
				a = janus_sdp_attribute_create("fmtp", "%d profile-level-id=%s;packetization-mode=1",
					pt, h264_profile);
				m->attributes = g_list_append(m->attributes, a);
			} else if(fmtp) {
				/* There's a custom fmtp line to add for video */
				a = janus_sdp_attribute_create("fmtp", "%d %s", pt, fmtp);
				m->attributes = g_list_append(m->attributes, a);
			}
		}
	} else {
		m->fmts = g_list_append(m->fmts, g_strdup(data_legacy ? "5000" : "webrtc-datachannel"));
		/* Add an sctpmap attribute */
		if(data_legacy) {
			a = janus_sdp_attribute_create("sctpmap", "5000 webrtc-datachannel 16");
			m->attributes = g_list_append(m->attributes, a);
		} else {
			a = janus_sdp_attribute_create("sctp-port", "5000");
			m->attributes = g_list_append(m->attributes, a);
		}
	}
	offer->m_lines = g_list_append(offer->m_lines, m);

	if(extmaps != NULL)
		g_hash_table_destroy(extmaps);
	if(extids_allocated) {
		if(extids != NULL)
			g_hash_table_destroy(extids);
	}

	/* Done */
	va_end(args);

	return 0;
}

janus_sdp *janus_sdp_generate_answer(janus_sdp *offer) {
	if(offer == NULL)
		return NULL;

	janus_refcount_increase(&offer->ref);
	/* Create an SDP answer, and start by copying some of the headers */
	janus_sdp *answer = g_malloc(sizeof(janus_sdp));
	g_atomic_int_set(&answer->destroyed, 0);
	janus_refcount_init(&answer->ref, janus_sdp_free);
	answer->version = offer->version;
	answer->o_name = g_strdup(offer->o_name ? offer->o_name : "-");
	answer->o_sessid = offer->o_sessid;
	answer->o_version = offer->o_version;
	answer->o_ipv4 = offer->o_ipv4;
	answer->o_addr = g_strdup(offer->o_addr ? offer->o_addr : "127.0.0.1");
	answer->s_name = g_strdup(offer->s_name ? offer->s_name : "Janus session");
	answer->t_start = 0;
	answer->t_stop = 0;
	answer->c_ipv4 = offer->c_ipv4;
	answer->c_addr = g_strdup(offer->c_addr ? offer->c_addr : "127.0.0.1");
	answer->attributes = NULL;
	answer->m_lines = NULL;

	/* Iterate on all m-lines to add, if any */
	GList *temp = offer->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		/* For each m-line we parse, we'll need a corresponding one in the answer */
		janus_sdp_mline *am = g_malloc0(sizeof(janus_sdp_mline));
		janus_refcount_init(&am->ref, janus_sdp_mline_free);
		am->index = m->index;
		am->type = m->type;
		am->type_str = m->type_str ? g_strdup(m->type_str) : NULL;
		am->proto = g_strdup(m->proto ? m->proto : "UDP/TLS/RTP/SAVPF");
		am->c_ipv4 = m->c_ipv4;
		am->c_addr = g_strdup(am->c_addr ? am->c_addr : "127.0.0.1");
		/* We reject the media line by default, but this can be changed later */
		am->port = 0;
		am->direction = JANUS_SDP_INACTIVE;
		am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(0));
		if(am->type == JANUS_SDP_APPLICATION) {
			GList *fmt = m->fmts;
			while(fmt) {
				char *fmt_str = (char *)fmt->data;
				if(fmt_str)
					am->fmts = g_list_append(am->fmts, g_strdup(fmt_str));
				fmt = fmt->next;
			}
		}
		/* Append to the list of m-lines in the answer */
		answer->m_lines = g_list_append(answer->m_lines, am);
		temp = temp->next;
	}
	janus_refcount_decrease(&offer->ref);

	/* Done*/
	return answer;
}

int janus_sdp_generate_answer_mline(janus_sdp *offer, janus_sdp *answer, janus_sdp_mline *offered, ...) {
	if(answer == NULL || offered == NULL)
		return -1;

	janus_refcount_increase(&offer->ref);
	janus_refcount_increase(&answer->ref);
	/* This method has a variable list of arguments, telling us how we should respond */
	va_list args;
	va_start(args, offered);

	/* Let's see what we should do with the media */
	gboolean mline_enabled = TRUE;
	janus_sdp_mtype type = JANUS_SDP_OTHER;
	gboolean audio_dtmf = FALSE, audio_opusred = FALSE, video_rtcpfb = TRUE;
	const char *codec = NULL, *msid = NULL, *mstid = NULL,
		*fmtp = NULL, *vp9_profile = NULL, *h264_profile = NULL;
	char *custom_audio_fmtp = NULL;
	GList *extmaps = NULL;
	janus_sdp_mdirection mdir = JANUS_SDP_DEFAULT;
	int property = va_arg(args, int);
	if(property != JANUS_SDP_OA_MLINE) {
		/* The first attribute MUST be JANUS_SDP_OA_MLINE */
		JANUS_LOG(LOG_ERR, "First attribute is not JANUS_SDP_OA_MLINE\n");
		va_end(args);
		janus_refcount_decrease(&offer->ref);
		janus_refcount_decrease(&answer->ref);
		return -2;
	}
	type = va_arg(args, int);
	if(type != JANUS_SDP_AUDIO && type != JANUS_SDP_VIDEO && type != JANUS_SDP_APPLICATION) {
		/* Unsupported m-line type */
		JANUS_LOG(LOG_ERR, "Invalid m-line type\n");
		va_end(args);
		janus_refcount_decrease(&offer->ref);
		janus_refcount_decrease(&answer->ref);
		return -3;
	}

	/* Let's see what we should do with the media to add */
	property = va_arg(args, int);
	while(property != JANUS_SDP_OA_DONE) {
		if(property == JANUS_SDP_OA_ENABLED) {
			mline_enabled = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_DIRECTION) {
			mdir = va_arg(args, janus_sdp_mdirection);
		} else if(property == JANUS_SDP_OA_CODEC) {
			codec = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_MSID) {
			msid = va_arg(args, char *);
			mstid = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_FMTP) {
			fmtp = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_VP9_PROFILE) {
			vp9_profile = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_H264_PROFILE) {
			h264_profile = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_AUDIO_DTMF) {
			audio_dtmf = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS) {
			video_rtcpfb = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_ACCEPT_EXTMAP) {
			const char *extension = va_arg(args, char *);
			if(extension != NULL)
				extmaps = g_list_append(extmaps, (char *)extension);
		} else if(property == JANUS_SDP_OA_ACCEPT_OPUSRED) {
			audio_opusred = va_arg(args, gboolean);
		} else {
			JANUS_LOG(LOG_WARN, "Unknown property %d for preparing SDP answer, ignoring...\n", property);
		}
		property = va_arg(args, int);
	}

	/* Iterate on all m-lines to add, if any, to find the one with the same index */
	GList *temp = answer->m_lines;
	while(temp) {
		janus_sdp_mline *am = (janus_sdp_mline *)temp->data;
		if(am->index != offered->index) {
			temp = temp->next;
			continue;
		}
		/* When answering, m-lines are disabled by default */
		am->direction = JANUS_SDP_INACTIVE;
		g_list_free(am->ptypes);
		am->ptypes = NULL;
		g_list_free_full(am->fmts, (GDestroyNotify)g_free);
		am->fmts = NULL;
		g_list_free_full(am->attributes, (GDestroyNotify)janus_sdp_attribute_destroy);
		am->attributes = NULL;
		if(!mline_enabled) {
			am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(0));
			if(am->type == JANUS_SDP_APPLICATION) {
				GList *fmt = offered->fmts;
				while(fmt) {
					char *fmt_str = (char *)fmt->data;
					if(fmt_str)
						am->fmts = g_list_append(am->fmts, g_strdup(fmt_str));
					fmt = fmt->next;
				}
			}
			break;
		}
		am->port = 9;
		if(am->type == JANUS_SDP_AUDIO || am->type == JANUS_SDP_VIDEO) {
			/* What is the direction we were offered? And how were we asked to react?
			 * Adapt the direction in our answer accordingly */
			switch(offered->direction) {
				case JANUS_SDP_RECVONLY:
					if(mdir == JANUS_SDP_SENDRECV || mdir == JANUS_SDP_DEFAULT || mdir == JANUS_SDP_SENDONLY) {
						/* Peer is recvonly, we'll only send */
						am->direction = JANUS_SDP_SENDONLY;
					} else {
						/* Peer is recvonly, but we're not ok to send, so reply with inactive */
						JANUS_LOG(LOG_WARN, "%s offered as '%s', but we need '%s' for us: using 'inactive'\n",
							am->type == JANUS_SDP_AUDIO ? "Audio" : "Video",
							janus_sdp_mdirection_str(offered->direction), janus_sdp_mdirection_str(mdir));
						am->direction = JANUS_SDP_INACTIVE;
					}
					break;
				case JANUS_SDP_SENDONLY:
					if(mdir == JANUS_SDP_SENDRECV || mdir == JANUS_SDP_DEFAULT || mdir == JANUS_SDP_RECVONLY) {
						/* Peer is sendonly, we'll only receive */
						am->direction = JANUS_SDP_RECVONLY;
					} else {
						/* Peer is sendonly, but we're not ok to receive, so reply with inactive */
						JANUS_LOG(LOG_WARN, "%s offered as '%s', but we need '%s' for us: using 'inactive'\n",
							am->type == JANUS_SDP_AUDIO ? "Audio" : "Video",
							janus_sdp_mdirection_str(offered->direction), janus_sdp_mdirection_str(mdir));
						am->direction = JANUS_SDP_INACTIVE;
					}
					break;
				case JANUS_SDP_INACTIVE:
					/* Peer inactive, set inactive in the answer to */
					am->direction = JANUS_SDP_INACTIVE;
					break;
				case JANUS_SDP_SENDRECV:
				default:
					/* The peer is fine with everything, so use our constraint */
					am->direction = mdir;
					break;
			}
			/* Look for the right codec and stick to that */
			if(codec == NULL) {
				/* FIXME User didn't provide a codec to accept? Let's see if Opus (for audio)
				 * of VP8 (for video) were negotiated: if so, use them, otherwise let's
				 * pick some other codec we know about among the ones that were offered.
				 * Notice that if it's not a codec we understand, we reject the medium,
				 * as browsers would reject it anyway. If you need more flexibility you'll
				 * have to generate an answer yourself, rather than automatically... */
				codec = am->type == JANUS_SDP_AUDIO ? "opus" : "vp8";
				if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
					/* We couldn't find our preferred codec, let's try something else */
					if(am->type == JANUS_SDP_AUDIO) {
						/* Opus not found, maybe mu-law? */
						codec = "pcmu";
						if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
							/* mu-law not found, maybe a-law? */
							codec = "pcma";
							if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
								/* a-law not found, maybe G.722? */
								codec = "g722";
								if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
									/* G.722 not found, maybe isac32? */
									codec = "isac32";
									if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
										/* isac32 not found, maybe isac16? */
										codec = "isac16";
										if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
											/* isac16 not found, maybe multiopus? */
											codec = "multiopus";
											if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
												/* multiopus not found, maybe L16/48000? */
												codec = "l16-48";
												if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
													/* L16/48000 not found, maybe L16/16000? */
													codec = "l16";
												}
											}
										}
									}
								}
							}
						}
					} else {
						/* VP8 not found, maybe VP9? */
						codec = "vp9";
						if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
							/* VP9 not found either, maybe H.264? */
							codec = "h264";
							if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
								/* H.264 not found either, maybe AV1? */
								codec = "av1";
								if(janus_sdp_get_codec_pt(offer, offered->index, codec) < 0) {
									/* AV1 not found either, maybe H.265? */
									codec = "h265";
								}
							}
						}
					}
				}
			}
			const char *video_profile = NULL;
			if(codec && !strcasecmp(codec, "vp9"))
				video_profile = vp9_profile;
			else if(codec && !strcasecmp(codec, "h264"))
				video_profile = h264_profile;
			int pt = janus_sdp_get_codec_pt_full(offer, offered->index, codec, video_profile);
			if(pt < 0) {
				/* Reject */
				JANUS_LOG(LOG_WARN, "Couldn't find codec we needed (%s) in the offer, rejecting %s\n",
					codec, am->type == JANUS_SDP_AUDIO ? "audio" : "video");
				am->port = 0;
				am->direction = JANUS_SDP_INACTIVE;
				am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(0));
				break;
			}
			if(am->type == JANUS_SDP_AUDIO && !strcasecmp(codec, "multiopus") &&
					(fmtp == NULL || strstr(fmtp, "channel_mapping") == NULL)) {
				/* Missing channel mapping for the multiopus m-line, check the offer */
				GList *mo = offered->attributes;
				while(mo) {
					janus_sdp_attribute *a = (janus_sdp_attribute *)mo->data;
					if(a->name && strstr(a->name, "fmtp") && a->value) {
						char *tmp = strchr(a->value, ' ');
						if(tmp && strlen(tmp) > 1 && custom_audio_fmtp == NULL) {
							tmp++;
							custom_audio_fmtp = g_strdup(tmp);
							/* FIXME We should integrate the existing audio_fmtp */
						}
						break;
					}
					mo = mo->next;
				}
			}
			am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(pt));
			/* Any msid we should set? */
			if(msid != NULL && mstid != NULL) {
				janus_sdp_attribute *a = janus_sdp_attribute_create("msid", "%s %s", msid, mstid);
				am->attributes = g_list_append(am->attributes, a);
			}
			/* Add the related attributes */
			if(am->type == JANUS_SDP_AUDIO) {
				/* Add rtpmap attribute */
				int opusred_pt = -1;
				const char *codec_rtpmap = janus_sdp_get_codec_rtpmap(codec);
				janus_sdp_attribute *a = NULL;
				if(codec_rtpmap) {
					/* If we're supposed to negotiate opus/red as well, check if it's there */
					if(!strcasecmp(codec, "opus") && audio_opusred) {
						opusred_pt = janus_sdp_get_opusred_pt(offer, am->index);
						if(opusred_pt > 0) {
							/* Add rtpmap attribute for opus/red too */
							am->ptypes = g_list_prepend(am->ptypes, GINT_TO_POINTER(opusred_pt));
							a = janus_sdp_attribute_create("rtpmap", "%d red/48000/2", opusred_pt);
							am->attributes = g_list_append(am->attributes, a);
						}
					}
					a = janus_sdp_attribute_create("rtpmap", "%d %s", pt, codec_rtpmap);
					am->attributes = g_list_append(am->attributes, a);
					/* Check if we need to add a payload type for DTMF tones (telephone-event/8000) */
					if(audio_dtmf) {
						int dtmf_pt = janus_sdp_get_codec_pt(offer, am->index, "dtmf");
						if(dtmf_pt >= 0) {
							/* We do */
							am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(dtmf_pt));
							a = janus_sdp_attribute_create("rtpmap", "%d %s", dtmf_pt, janus_sdp_get_codec_rtpmap("dtmf"));
							am->attributes = g_list_append(am->attributes, a);
						}
					}
					/* If we're negotiating opus/red, add an fmtp line for that */
					if(audio_opusred && opusred_pt > 0) {
						a = janus_sdp_attribute_create("fmtp", "%d %d/%d", opusred_pt, pt, pt);
						am->attributes = g_list_append(am->attributes, a);
					}
					/* Check if there's a custom fmtp line to add for audio
					 * FIXME We should actually check if it matches the offer */
					if(fmtp || custom_audio_fmtp) {
						a = janus_sdp_attribute_create("fmtp", "%d %s",
							pt, custom_audio_fmtp ? custom_audio_fmtp : fmtp);
						am->attributes = g_list_append(am->attributes, a);
					}
				}
			} else {
				/* Add rtpmap attribute */
				const char *codec_rtpmap = janus_sdp_get_codec_rtpmap(codec);
				janus_sdp_attribute *a = NULL;
				if(codec_rtpmap) {
					a = janus_sdp_attribute_create("rtpmap", "%d %s", pt, codec_rtpmap);
					am->attributes = g_list_append(am->attributes, a);
					if(video_rtcpfb) {
						/* Add rtcp-fb attributes */
						a = janus_sdp_attribute_create("rtcp-fb", "%d ccm fir", pt);
						am->attributes = g_list_append(am->attributes, a);
						a = janus_sdp_attribute_create("rtcp-fb", "%d nack", pt);
						am->attributes = g_list_append(am->attributes, a);
						a = janus_sdp_attribute_create("rtcp-fb", "%d nack pli", pt);
						am->attributes = g_list_append(am->attributes, a);
						a = janus_sdp_attribute_create("rtcp-fb", "%d goog-remb", pt);
						am->attributes = g_list_append(am->attributes, a);
					}
					/* It is safe to add transport-wide rtcp feedback message here, won't be used unless the header extension is negotiated*/
					a = janus_sdp_attribute_create("rtcp-fb", "%d transport-cc", pt);
					am->attributes = g_list_append(am->attributes, a);
				}
				if(!strcasecmp(codec, "vp9") && vp9_profile) {
					/* Add a profile-id fmtp attribute */
					a = janus_sdp_attribute_create("fmtp", "%d profile-id=%s", pt, vp9_profile);
					am->attributes = g_list_append(am->attributes, a);
				} else if(!strcasecmp(codec, "h264") && h264_profile) {
					/* Add a profile-level-id fmtp attribute */
					a = janus_sdp_attribute_create("fmtp", "%d profile-level-id=%s;packetization-mode=1", pt, h264_profile);
					am->attributes = g_list_append(am->attributes, a);
				} else if(fmtp) {
					/* There's a custom fmtp line to add for video
					 * FIXME We should actually check if it matches the offer */
					a = janus_sdp_attribute_create("fmtp", "%d %s", pt, fmtp);
					am->attributes = g_list_append(am->attributes, a);
				}
			}
			/* Add the extmap attributes, if needed */
			if(extmaps != NULL) {
				GList *ma = offered->attributes;
				while(ma) {
					/* Iterate on all attributes, to see if there's an extension to accept */
					janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
					if(a->name && strstr(a->name, "extmap") && a->value) {
						GList *emtemp = extmaps;
						while(emtemp != NULL) {
							char *extension = (char *)emtemp->data;
							if(strstr(a->value, extension)) {
								/* Accept the extension */
								int id = atoi(a->value);
								if(id < 0) {
									JANUS_LOG(LOG_ERR, "Invalid extension ID (%d)\n", id);
									emtemp = emtemp->next;
									continue;
								}

								if(strstr(a->value, JANUS_RTP_EXTMAP_DEPENDENCY_DESC) &&
										strcasecmp(codec, "av1") && strcasecmp(codec, "vp9")) {
									/* Don't negotiate the Dependency Descriptor extension,
									 * unless we're doing AV1 or VP9 for SVC. See for ref:
									 * https://issues.webrtc.org/issues/42226269 */
									emtemp = emtemp->next;
									continue;
								}
								const char *direction = NULL;
								switch(a->direction) {
									case JANUS_SDP_SENDONLY:
										direction = "/recvonly";
										break;
									case JANUS_SDP_RECVONLY:
										direction = "/sendonly";
										break;
									case JANUS_SDP_INACTIVE:
										direction = "/inactive";
										break;
									default:
										direction = "";
										break;
								}
								a = janus_sdp_attribute_create("extmap",
									"%d%s %s", id, direction, extension);
								janus_sdp_attribute_add_to_mline(am, a);
							}
							emtemp = emtemp->next;
						}
					} else if(am->type == JANUS_SDP_VIDEO && a->name && strstr(a->name, "fmtp") &&
							a->value && atoi(a->value) == pt) {
						/* Check if we need to copy the fmtp attribute too */
						if(((!strcasecmp(codec, "vp8") && fmtp == NULL)) ||
								((!strcasecmp(codec, "vp9") && vp9_profile == NULL && fmtp == NULL)) ||
								((!strcasecmp(codec, "h264") && h264_profile == NULL && fmtp == NULL))) {
							/* FIXME Copy the fmtp attribute (we should check if we support it) */
							a = janus_sdp_attribute_create("fmtp", "%s", a->value);
							janus_sdp_attribute_add_to_mline(am, a);
						}
					}
					ma = ma->next;
				}
			}
		} else {
			/* This is for data, add formats and an sctpmap attribute */
			am->direction = JANUS_SDP_DEFAULT;
			GList *fmt = offered->fmts;
			while(fmt) {
				char *fmt_str = (char *)fmt->data;
				if(fmt_str)
					am->fmts = g_list_append(am->fmts, g_strdup(fmt_str));
				fmt = fmt->next;
			}
		}
		/* Nothing else we need to do */
		break;
	}
	janus_refcount_decrease(&offer->ref);
	janus_refcount_decrease(&answer->ref);

	/* Done */
	g_list_free(extmaps);
	g_free(custom_audio_fmtp);
	va_end(args);

	return 0;
}
