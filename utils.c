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
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

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

guint32 janus_random_uint32(void) {
	return g_random_int();
}

guint64 janus_random_uint64(void) {
	/*
	 * FIXME This needs to be improved, and use something that generates
	 * more strongly random stuff... using /dev/urandom is probably not
	 * a good idea, as we don't want to make it harder to cross compile Janus
	 *
	 * TODO Look into what libssl and/or libcrypto provide in that respect
	 *
	 * PS: JavaScript only supports integer up to 2^53, so we need to
	 * make sure the number is below 9007199254740992 for safety
	 */
	guint64 num = g_random_int() & 0x1FFFFF;
	num = (num << 32) | g_random_int();
	return num;
}

guint64 *janus_uint64_dup(guint64 num) {
	guint64 *numdup = g_malloc0(sizeof(guint64));
	memcpy(numdup, &num, sizeof(num));
	return numdup;
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

/* Easy way to replace multiple occurrences of a string with another */
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

int janus_get_codec_pt(const char *sdp, const char *codec) {
	if(!sdp || !codec)
		return -1;
	int video = 0;
	const char *format = NULL, *format2 = NULL;
	if(!strcasecmp(codec, "opus")) {
		video = 0;
		format = "opus/48000/2";
		format2 = "OPUS/48000/2";
	} else if(!strcasecmp(codec, "pcmu")) {
		/* We know the payload type is 0: we just need to make sure it's there */
		video = 0;
		format = "pcmu/8000";
		format2 = "PCMU/8000";
	} else if(!strcasecmp(codec, "pcma")) {
		/* We know the payload type is 8: we just need to make sure it's there */
		video = 0;
		format = "pcma/8000";
		format2 = "PCMA/8000";
	} else if(!strcasecmp(codec, "isac16")) {
		video = 0;
		format = "isac/16000";
		format2 = "ISAC/16000";
	} else if(!strcasecmp(codec, "isac32")) {
		video = 0;
		format = "isac/32000";
		format2 = "ISAC/32000";
	} else if(!strcasecmp(codec, "vp8")) {
		video = 1;
		format = "vp8/90000";
		format2 = "VP8/90000";
	} else if(!strcasecmp(codec, "vp9")) {
		video = 1;
		format = "vp9/90000";
		format2 = "VP9/90000";
	} else if(!strcasecmp(codec, "h264")) {
		video = 1;
		format = "h264/90000";
		format2 = "H264/90000";
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
		return -1;
	}
	/* First of all, let's check if the codec is there */
	if(!video) {
		if(!strstr(sdp, "m=audio") || (!strstr(sdp, format) && !strstr(sdp, format2)))
			return -2;
	} else {
		if(!strstr(sdp, "m=video") || (!strstr(sdp, format) && !strstr(sdp, format2)))
			return -2;
	}
	char rtpmap[50], rtpmap2[50];
	g_snprintf(rtpmap, 50, "a=rtpmap:%%d %s", format);
	g_snprintf(rtpmap2, 50, "a=rtpmap:%%d %s", format2);
	/* Look for the mapping */
	const char *line = strstr(sdp, video ? "m=video" : "m=audio");
	while(line) {
		char *next = strchr(line, '\n');
		if(next) {
			*next = '\0';
			if(strstr(line, "a=rtpmap") && strstr(line, format)) {
				/* Gotcha! */
				int pt = 0;
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
				if(sscanf(line, rtpmap, &pt) == 1) {
					*next = '\n';
					return pt;
				}
			} else if(strstr(line, "a=rtpmap") && strstr(line, format2)) {
				/* Gotcha! */
				int pt = 0;
				if(sscanf(line, rtpmap2, &pt) == 1) {
#pragma GCC diagnostic warning "-Wformat-nonliteral"
					*next = '\n';
					return pt;
				}
			}
			*next = '\n';
		}
		line = next ? (next+1) : NULL;
	}
	return -3;
}

const char *janus_get_codec_from_pt(const char *sdp, int pt) {
	if(!sdp || pt < 0)
		return NULL;
	if(pt == 0)
		return "pcmu";
	if(pt == 8)
		return "pcma";
	/* Look for the mapping */
	char rtpmap[50];
	g_snprintf(rtpmap, 50, "a=rtpmap:%d ", pt);
	const char *line = strstr(sdp, "m=");
	while(line) {
		char *next = strchr(line, '\n');
		if(next) {
			*next = '\0';
			if(strstr(line, rtpmap)) {
				/* Gotcha! */
				char name[100];
				if(sscanf(line, "a=rtpmap:%d %s", &pt, name) == 2) {
					*next = '\n';
					if(strstr(name, "vp8") || strstr(name, "VP8"))
						return "vp8";
					if(strstr(name, "vp9") || strstr(name, "VP9"))
						return "vp9";
					if(strstr(name, "h264") || strstr(name, "H264"))
						return "h264";
					if(strstr(name, "opus") || strstr(name, "OPUS"))
						return "opus";
					if(strstr(name, "pcmu") || strstr(name, "PMCU"))
						return "pcmu";
					if(strstr(name, "pcma") || strstr(name, "PMCA"))
						return "pcma";
					if(strstr(name, "isac/16") || strstr(name, "ISAC/16"))
						return "isac16";
					if(strstr(name, "isac/32") || strstr(name, "ISAC/32"))
						return "isac32";
					JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", name);
					return NULL;
				}
			}
			*next = '\n';
		}
		line = next ? (next+1) : NULL;
	}
	return NULL;
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

/* PID file management */
static char *pidfile = NULL;
static int pidfd = -1;
static FILE *pidf = NULL;
int janus_pidfile_create(const char *file) {
	if(file == NULL)
		return 0;
	pidfile = g_strdup(file);
	/* Try creating a PID file (or opening an existing one) */
	pidfd = open(pidfile, O_RDWR|O_CREAT, 0644);
	if(pidfd < 0) {
		JANUS_LOG(LOG_FATAL, "Error opening/creating PID file %s, does Janus have enough permissions?\n", pidfile);
		return -1;
	}
	pidf = fdopen(pidfd, "r+");
	if(pidf == NULL) {
		JANUS_LOG(LOG_FATAL, "Error opening/creating PID file %s, does Janus have enough permissions?\n", pidfile);
		close(pidfd);
		return -1;
	}
	/* Try locking the PID file */
	int pid = 0;
	if(flock(pidfd, LOCK_EX|LOCK_NB) < 0) {
		if(fscanf(pidf, "%d", &pid) == 1) {
			JANUS_LOG(LOG_FATAL, "Error locking PID file (lock held by PID %d?)\n", pid);
		} else {
			JANUS_LOG(LOG_FATAL, "Error locking PID file (lock held by unknown PID?)\n");
		}
		fclose(pidf);
		return -1;
	}
	/* Write the PID */
	pid = getpid();
	if(fprintf(pidf, "%d\n", pid) < 0) {
		JANUS_LOG(LOG_FATAL, "Error writing PID in file, error %d (%s)\n", errno, strerror(errno));
		fclose(pidf);
		return -1;
	}
	fflush(pidf);
	/* We're done */
	return 0;
}

int janus_pidfile_remove(void) {
	if(pidfile == NULL || pidfd < 0 || pidf == NULL)
		return 0;
	/* Unlock the PID file and remove it */
	if(flock(pidfd, LOCK_UN) < 0) {
		JANUS_LOG(LOG_FATAL, "Error unlocking PID file\n");
		fclose(pidf);
		close(pidfd);
		return -1;
	}
	fclose(pidf);
	unlink(pidfile);
	g_free(pidfile);
	return 0;
}

void janus_get_json_type_name(int jtype, unsigned int flags, char *type_name) {
	/* Longest possible combination is "a non-empty boolean" plus one for null char */
	gsize req_size = 20;
	/* Don't allow for both "positive" and "non-empty" because that needlessly increases the size. */
	if((flags & JANUS_JSON_PARAM_POSITIVE) != 0) {
		g_strlcpy(type_name, "a positive ", req_size);
	}
	else if((flags & JANUS_JSON_PARAM_NONEMPTY) != 0) {
		g_strlcpy(type_name, "a non-empty ", req_size);
	}
	else if(jtype == JSON_INTEGER || jtype == JSON_ARRAY || jtype == JSON_OBJECT) {
		g_strlcpy(type_name, "an ", req_size);
	}
	else {
		g_strlcpy(type_name, "a ", req_size);
	}
	switch(jtype) {
		case JSON_TRUE:
			g_strlcat(type_name, "boolean", req_size);
			break;
		case JSON_INTEGER:
			g_strlcat(type_name, "integer", req_size);
			break;
		case JSON_REAL:
			g_strlcat(type_name, "real", req_size);
			break;
		case JSON_STRING:
			g_strlcat(type_name, "string", req_size);
			break;
		case JSON_ARRAY:
			g_strlcat(type_name, "array", req_size);
			break;
		case JSON_OBJECT:
			g_strlcat(type_name, "object", req_size);
			break;
		default:
			break;
	}
}

gboolean janus_json_is_valid(json_t *val, json_type jtype, unsigned int flags) {
	gboolean is_valid = (json_typeof(val) == jtype || (jtype == JSON_TRUE && json_typeof(val) == JSON_FALSE));
	if(!is_valid)
		return FALSE;
	if((flags & JANUS_JSON_PARAM_POSITIVE) != 0) {
		switch(jtype) {
			case JSON_INTEGER:
				is_valid = (json_integer_value(val) >= 0);
				break;
			case JSON_REAL:
				is_valid = (json_real_value(val) >= 0);
				break;
			default:
				break;
		}
	}
	else if((flags & JANUS_JSON_PARAM_NONEMPTY) != 0) {
		switch(jtype) {
			case JSON_STRING:
				is_valid = (strlen(json_string_value(val)) > 0);
				break;
			case JSON_ARRAY:
				is_valid = (json_array_size(val) > 0);
				break;
			default:
				break;
		}
	}
	return is_valid;
}
