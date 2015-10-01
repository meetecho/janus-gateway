/*! \file    utils.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Utilities and helpers
 * \details  Implementations of a few methods that may be of use here
 * and there in the code.
 * 
 * \ingroup core
 * \ref core
 */

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "utils.h"
#include "debug.h"

#if __MACH__
#include "mach_gettime.h"
#endif

gint64 janus_get_monotonic_time(void) {
	struct timespec ts;
	clock_gettime (CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec*G_GINT64_CONSTANT(1000000)) + (ts.tv_nsec/G_GINT64_CONSTANT(1000));
}

gint64 janus_get_real_time(void) {
	struct timespec ts;
	clock_gettime (CLOCK_REALTIME, &ts);
	return (ts.tv_sec*G_GINT64_CONSTANT(1000000)) + (ts.tv_nsec/G_GINT64_CONSTANT(1000));
}

gboolean janus_is_true(const char *value) {
	return value && (!strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "1"));
}

gboolean janus_strcmp_const_time(const void *str1, const void *str2) {
	if(str1 == NULL || str2 == NULL)
		return FALSE;
	const unsigned char *string1 = (const unsigned char *)str1;
	const unsigned char *string2 = (const unsigned char *)str2;
	size_t maxlen = strlen((char *)string1);
	if(strlen((char *)string2) > maxlen)
		maxlen = strlen((char *)string2);
	unsigned char *buf1 = g_malloc0(maxlen+1);
	memset(buf1, 0, maxlen);
	memcpy(buf1, string1, strlen(str1));
	unsigned char *buf2 = g_malloc0(maxlen+1);
	memset(buf2, 0, maxlen);
	memcpy(buf2, string2, strlen(str2));
	unsigned char result = 0;
	size_t i = 0;
	for (i = 0; i < maxlen; i++) {
		result |= buf1[i] ^ buf2[i];
	}
	g_free(buf1);
	buf1 = NULL;
	g_free(buf2);
	buf2 = NULL;
	return result == 0;
}

void janus_flags_reset(janus_flags *flags) {
	if(flags != NULL)
		*flags = 0;
}

void janus_flags_set(janus_flags *flags, uint32_t flag) {
	if(flags != NULL) {
		*flags |= flag;
	}
}

void janus_flags_clear(janus_flags *flags, uint32_t flag) {
	if(flags != NULL) {
		*flags &= ~(flag);
	}
}

gboolean janus_flags_is_set(janus_flags *flags, uint32_t flag) {
	if(flags != NULL) {
		uint32_t bit = *flags & flag;
		return (bit != 0);
	}
	return FALSE;
}

/* Easy way to replace multiple occurrences of a string with another: ALWAYS creates a NEW string */
char *janus_string_replace(char *message, const char *old_string, const char *new_string)
{
	if(!message || !old_string || !new_string)
		return NULL;

	if(!strstr(message, old_string)) {	/* Nothing to be done (old_string is not there) */
		return message;
	}
	if(!strcmp(old_string, new_string)) {	/* Nothing to be done (old_string=new_string) */
		return message;
	}
	if(strlen(old_string) == strlen(new_string)) {	/* Just overwrite */
		char *outgoing = message;
		char *pos = strstr(outgoing, old_string), *tmp = NULL;
		int i = 0;
		while(pos) {
			i++;
			memcpy(pos, new_string, strlen(new_string));
			pos += strlen(old_string);
			tmp = strstr(pos, old_string);
			pos = tmp;
		}
		return outgoing;
	} else {	/* We need to resize */
		char *outgoing = g_strdup(message);
		g_free(message);
		if(outgoing == NULL) {
			return NULL;
		}
		int diff = strlen(new_string) - strlen(old_string);
		/* Count occurrences */
		int counter = 0;
		char *pos = strstr(outgoing, old_string), *tmp = NULL;
		while(pos) {
			counter++;
			pos += strlen(old_string);
			tmp = strstr(pos, old_string);
			pos = tmp;
		}
		uint16_t old_stringlen = strlen(outgoing)+1, new_stringlen = old_stringlen + diff*counter;
		if(diff > 0) {	/* Resize now */
			tmp = g_realloc(outgoing, new_stringlen);
			if(!tmp) {
				g_free(outgoing);
				return NULL;
			}
			outgoing = tmp;
		}
		/* Replace string */
		pos = strstr(outgoing, old_string);
		while(pos) {
			if(diff > 0) {	/* Move to the right (new_string is larger than old_string) */
				uint16_t len = strlen(pos)+1;
				memmove(pos + diff, pos, len);
				memcpy(pos, new_string, strlen(new_string));
				pos += strlen(new_string);
				tmp = strstr(pos, old_string);
			} else {	/* Move to the left (new_string is smaller than old_string) */
				uint16_t len = strlen(pos - diff)+1;
				memmove(pos, pos - diff, len);
				memcpy(pos, new_string, strlen(new_string));
				pos += strlen(old_string);
				tmp = strstr(pos, old_string);
			}
			pos = tmp;
		}
		if(diff < 0) {	/* We skipped the resize previously (shrinking memory) */
			tmp = g_realloc(outgoing, new_stringlen);
			if(!tmp) {
				g_free(outgoing);
				return NULL;
			}
			outgoing = tmp;
		}
		outgoing[strlen(outgoing)] = '\0';
		return outgoing;
	}
}

int janus_mkdir(const char *dir, mode_t mode) {
	char tmp[256];
	char *p = NULL;
	size_t len;

	int res = 0;
	g_snprintf(tmp, sizeof(tmp), "%s", dir);
	len = strlen(tmp);
	if(tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for(p = tmp + 1; *p; p++) {
		if(*p == '/') {
			*p = 0;
			res = mkdir(tmp, mode);
			if(res != 0 && errno != EEXIST) {
				JANUS_LOG(LOG_ERR, "Error creating folder %s\n", tmp);
				return res;
			}
			*p = '/';
		}
	}
	res = mkdir(tmp, mode);
	if(res != 0 && errno != EEXIST)
		return res;
	return 0;
}

int janus_get_opus_pt(const char *sdp) {
	if(!sdp)
		return -1;
	if(!strstr(sdp, "m=audio") || !strstr(sdp, "opus/48000"))	/* FIXME Should be case insensitive */
		return -1;
	const char *line = strstr(sdp, "m=audio");
	while(line) {
		char *next = strchr(line, '\n');
		if(next) {
			*next = '\0';
			if(strstr(line, "a=rtpmap") && strstr(line, "opus/48000")) {
				/* Gotcha! */
				int pt = 0;
				if(sscanf(line, "a=rtpmap:%d opus/48000/2", &pt) == 1) {
					*next = '\n';
					return pt;
				}
			}
			*next = '\n';
		}
		line = next ? (next+1) : NULL;
	}
	return -1;
}

int janus_get_vp8_pt(const char *sdp) {
	if(!sdp)
		return -1;
	if(!strstr(sdp, "m=video") || !strstr(sdp, "VP8/90000"))	/* FIXME Should be case insensitive */
		return -1;
	const char *line = strstr(sdp, "m=video");
	while(line) {
		char *next = strchr(line, '\n');
		if(next) {
			*next = '\0';
			if(strstr(line, "a=rtpmap") && strstr(line, "VP8/90000")) {
				/* Gotcha! */
				int pt = 0;
				if(sscanf(line, "a=rtpmap:%d VP8/90000", &pt) == 1) {
					*next = '\n';
					return pt;
				}
			}
			*next = '\n';
		}
		line = next ? (next+1) : NULL;
	}
	return -1;
}

gboolean janus_is_ip_valid(const char *ip, int *family) {
	if(ip == NULL)
		return FALSE;

	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;

	if(inet_pton(AF_INET, ip, &addr4) > 0) {
		if(family != NULL)
			*family = AF_INET;
		return TRUE;
	} else if(inet_pton(AF_INET6, ip, &addr6) > 0) {
		if(family != NULL)
			*family = AF_INET6;
		return TRUE;
	} else {
		return FALSE;
	}
}

char *janus_address_to_ip(struct sockaddr *address) {
	if(address == NULL)
		return NULL;
	char addr_buf[INET6_ADDRSTRLEN];
	const char *addr = NULL;
	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;

	switch(address->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)address;
			addr = inet_ntop(AF_INET, &sin->sin_addr, addr_buf, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)address;
			addr = inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, INET6_ADDRSTRLEN);
			break;
		default:
			/* Unknown family */
			break;
	}
	return addr ? g_strdup(addr) : NULL;
}
