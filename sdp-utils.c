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
#include "utils.h"
#include "debug.h"

#define JANUS_BUFSIZE	8192

void janus_sdp_free(janus_sdp *sdp) {
	if(!sdp)
		return;
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
		g_free(m->type_str);
		g_free(m->proto);
		g_free(m->c_addr);
		g_free(m->b_name);
		g_list_free_full(m->fmts, (GDestroyNotify)g_free);
		m->fmts = NULL;
		g_list_free(m->ptypes);
		m->ptypes = NULL;
		GList *temp2 = m->attributes;
		while(temp2) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)temp2->data;
			janus_sdp_attribute_destroy(a);
			temp2 = temp2->next;
		}
		g_list_free(m->attributes);
		g_free(m);
		temp = temp->next;
	}
	g_list_free(sdp->m_lines);
	sdp->m_lines = NULL;
	g_free(sdp);
}

janus_sdp_attribute *janus_sdp_attribute_create(const char *name, const char *value, ...) {
	if(!name)
		return NULL;
	janus_sdp_attribute *a = g_malloc0(sizeof(janus_sdp_attribute));
	a->name = g_strdup(name);
	if(value) {
		char buffer[512];
		va_list ap;
		va_start(ap, value);
		g_vsnprintf(buffer, sizeof(buffer), value, ap);
		va_end(ap);
		a->value = g_strdup(buffer);
	}
	return a;
}

void janus_sdp_attribute_destroy(janus_sdp_attribute *attr) {
	if(!attr)
		return;
	g_free(attr->name);
	g_free(attr->value);
	g_free(attr);
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

	gboolean success = TRUE;
	janus_sdp_mline *mline = NULL;

	gchar **parts = g_strsplit(sdp, "\r\n", -1);
	if(parts) {
		int index = 0;
		char *line = NULL;
		while(success && (line = parts[index]) != NULL) {
			if(*line == '\0') {
				index++;
				continue;
			}
			if(strlen(line) < 3) {
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
						line += 2;
						char *semicolon = strchr(line, ':');
						if(semicolon == NULL) {
							a->name = g_strdup(line);
							a->value = NULL;
						} else {
							if(*(semicolon+1) == '\0') {
								if(error)
									g_snprintf(error, errlen, "Invalid a= line: %s", line);
								success = FALSE;
								break;
							}
							*semicolon = '\0';
							a->name = g_strdup(line);
							a->value = g_strdup(semicolon+1);
							*semicolon = ':';
						}
						imported->attributes = g_list_append(imported->attributes, a);
						break;
					}
					case 'm': {
						janus_sdp_mline *m = g_malloc0(sizeof(janus_sdp_mline));
						/* Start with media type, port and protocol */
						char type[32];
						char proto[64];
						if(sscanf(line, "m=%31s %"SCNu16" %63s %*s", type, &m->port, proto) != 3) {
							if(error)
								g_snprintf(error, errlen, "Invalid m= line: %s", line);
							success = FALSE;
							break;
						}
						if(!strcasecmp(type, "audio"))
							m->type = JANUS_SDP_AUDIO;
						else if(!strcasecmp(type, "video"))
							m->type = JANUS_SDP_VIDEO;
						else if(!strcasecmp(type, "application"))
							m->type = JANUS_SDP_APPLICATION;
						else
							m->type = JANUS_SDP_OTHER;
						m->type_str = g_strdup(type);
						m->proto = g_strdup(proto);
						m->direction = JANUS_SDP_SENDRECV;
						if(m->port > 0) {
							/* Now let's check the payload types/formats */
							gchar **mline_parts = g_strsplit(line+2, " ", -1);
							if(!mline_parts) {
								if(error)
									g_snprintf(error, errlen, "Invalid m= line (no payload types/formats): %s", line);
								success = FALSE;
								break;
							}
							int mindex = 0;
							while(mline_parts[mindex]) {
								if(mindex < 3) {
									/* We've parsed these before */
									mindex++;
									continue;
								}
								/* Add string fmt */
								m->fmts = g_list_append(m->fmts, g_strdup(mline_parts[mindex]));
								/* Add numeric payload type */
								int ptype = atoi(mline_parts[mindex]);
								m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(ptype));
								mindex++;
							}
							g_strfreev(mline_parts);
							if(m->fmts == NULL || m->ptypes == NULL) {
								if(error)
									g_snprintf(error, errlen, "Invalid m= line (no payload types/formats): %s", line);
								success = FALSE;
								break;
							}
						}
						/* Append to the list of m-lines */
						imported->m_lines = g_list_append(imported->m_lines, m);
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
						line += 2;
						char *semicolon = strchr(line, ':');
						if(semicolon == NULL || (*(semicolon+1) == '\0')) {
							if(error)
								g_snprintf(error, errlen, "Invalid b= line: %s", line);
							success = FALSE;
							break;
						}
						*semicolon = '\0';
						mline->b_name = g_strdup(line);
						mline->b_value = atoi(semicolon+1);
						*semicolon = ':';
						break;
					}
					case 'a': {
						janus_sdp_attribute *a = g_malloc0(sizeof(janus_sdp_attribute));
						line += 2;
						char *semicolon = strchr(line, ':');
						if(semicolon == NULL) {
							/* Is this a media direction attribute? */
							if(!strcasecmp(line, "sendrecv")) {
								g_free(a);
								mline->direction = JANUS_SDP_SENDRECV;
								break;
							} else if(!strcasecmp(line, "sendonly")) {
								g_free(a);
								mline->direction = JANUS_SDP_SENDONLY;
								break;
							} else if(!strcasecmp(line, "recvonly")) {
								g_free(a);
								mline->direction = JANUS_SDP_RECVONLY;
								break;
							} else if(!strcasecmp(line, "inactive")) {
								g_free(a);
								mline->direction = JANUS_SDP_INACTIVE;
								break;
							}
							a->name = g_strdup(line);
							a->value = NULL;
						} else {
							if(*(semicolon+1) == '\0') {
								if(error)
									g_snprintf(error, errlen, "Invalid a= line: %s", line);
								success = FALSE;
								break;
							}
							*semicolon = '\0';
							a->name = g_strdup(line);
							a->value = g_strdup(semicolon+1);
							*semicolon = ':';
						}
						mline->attributes = g_list_append(mline->attributes, a);
						break;
					}
					case 'm': {
						/* Current m-line ended, back to global parsing */
						mline = NULL;
						continue;
					}
					default:
						JANUS_LOG(LOG_WARN, "Ignoring '%c' property (m-line)\n", c);
						break;
				}
			}
			index++;
		}
		g_strfreev(parts);
	}
	/* FIXME Do a last check: is all the stuff that's supposed to be there available? */
	if(imported->o_name == NULL || imported->o_addr == NULL || imported->s_name == NULL || imported->m_lines == NULL) {
		success = FALSE;
		if(error)
			g_snprintf(error, errlen, "Missing mandatory lines (o=, s= or m=)");
	}
	/* If something wrong happened, free and return a failure */
	if(!success) {
		if(error)
			JANUS_LOG(LOG_ERR, "%s\n", error);
		janus_sdp_free(imported);
		imported = NULL;
	}
	return imported;
}

int janus_sdp_remove_payload_type(janus_sdp *sdp, int pt) {
	if(!sdp || pt < 0)
		return -1;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		/* Remove any reference from the m-line */
		m->ptypes = g_list_remove(m->ptypes, GINT_TO_POINTER(pt));
		/* Also remove all attributes that reference the same payload type */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(atoi(a->value) == pt) {
				m->attributes = g_list_remove(m->attributes, a);
				ma = m->attributes;
				janus_sdp_attribute_destroy(a);
				continue;
			}
			ma = ma->next;
		}
		ml = ml->next;
	}
	return 0;
}

char *janus_sdp_write(janus_sdp *imported) {
	if(!imported)
		return NULL;
	gboolean success = TRUE;
	char *sdp = g_malloc0(JANUS_BUFSIZE), buffer[512];
	*sdp = '\0';
	/* v= */
	g_snprintf(buffer, sizeof(buffer), "v=%d\r\n", imported->version);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* o= */
	g_snprintf(buffer, sizeof(buffer), "o=%s %"SCNu64" %"SCNu64" IN %s %s\r\n",
		imported->o_name, imported->o_sessid, imported->o_version,
		imported->o_ipv4 ? "IP4" : "IP6", imported->o_addr);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* s= */
	g_snprintf(buffer, sizeof(buffer), "s=%s\r\n", imported->s_name);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* t= */
	g_snprintf(buffer, sizeof(buffer), "t=%"SCNu64" %"SCNu64"\r\n", imported->t_start, imported->t_stop);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* c= */
	if(imported->c_addr != NULL) {
		g_snprintf(buffer, sizeof(buffer), "c=IN %s %s\r\n",
			imported->c_ipv4 ? "IP4" : "IP6", imported->c_addr);
		g_strlcat(sdp, buffer, JANUS_BUFSIZE);
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
		g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		temp = temp->next;
	}
	/* m= */
	temp = imported->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		g_snprintf(buffer, sizeof(buffer), "m=%s %d %s", m->type_str, m->port, m->proto);
		g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		if(m->port == 0) {
			/* Remove all payload types/formats if we're rejecting the media */
			g_list_free_full(m->fmts, (GDestroyNotify)g_free);
			m->fmts = NULL;
			g_list_free(m->ptypes);
			m->ptypes = NULL;
			m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(0));
			g_strlcat(sdp, " 0", JANUS_BUFSIZE);
		} else {
			if(strstr(m->proto, "RTP") != NULL) {
				/* RTP profile, use payload types */
				GList *ptypes = m->ptypes;
				while(ptypes) {
					g_snprintf(buffer, sizeof(buffer), " %d", GPOINTER_TO_INT(ptypes->data));
					g_strlcat(sdp, buffer, JANUS_BUFSIZE);
					ptypes = ptypes->next;
				}
			} else {
				/* Something else, use formats */
				GList *fmts = m->fmts;
				while(fmts) {
					g_snprintf(buffer, sizeof(buffer), " %s", (char *)(fmts->data));
					g_strlcat(sdp, buffer, JANUS_BUFSIZE);
					fmts = fmts->next;
				}
			}
		}
		g_strlcat(sdp, "\r\n", JANUS_BUFSIZE);
		/* c= */
		if(m->c_addr != NULL) {
			g_snprintf(buffer, sizeof(buffer), "c=IN %s %s\r\n",
				m->c_ipv4 ? "IP4" : "IP6", m->c_addr);
			g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		}
		if(m->port > 0) {
			/* b= */
			if(m->b_name != NULL) {
				g_snprintf(buffer, sizeof(buffer), "b=%s:%d\r\n", m->b_name, m->b_value);
				g_strlcat(sdp, buffer, JANUS_BUFSIZE);
			}
		}
		/* a= */
		const char *direction = NULL;
		switch(m->direction) {
			case JANUS_SDP_DEFAULT:
				/* Dob't write the direction */
				break;
			case JANUS_SDP_SENDONLY:
				direction = "sendonly";
				break;
			case JANUS_SDP_RECVONLY:
				direction = "recvonly";
				break;
			case JANUS_SDP_INACTIVE:
				direction = "inactive";
				break;
			case JANUS_SDP_SENDRECV:
			default:
				direction = "sendrecv";
				break;
		}
		if(direction != NULL) {
			g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", direction);
			g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		}
		if(m->port == 0) {
			/* No point going on */
			temp = temp->next;
			continue;
		}
		GList *temp2 = m->attributes;
		while(temp2) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)temp2->data;
			if(a->value != NULL) {
				g_snprintf(buffer, sizeof(buffer), "a=%s:%s\r\n", a->name, a->value);
			} else {
				g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", a->name);
			}
			g_strlcat(sdp, buffer, JANUS_BUFSIZE);
			temp2 = temp2->next;
		}
		temp = temp->next;
	}
	if(!success) {
		/* FIXME Never happens right now? */
		g_free(sdp);
		sdp = NULL;
	}
	return sdp;
}
