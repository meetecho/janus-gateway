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
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <zlib.h>
#include <openssl/rand.h>

#include "utils.h"
#include "debug.h"
#include "mutex.h"

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
	memcpy(buf1, string1, strlen(str1));
	unsigned char *buf2 = g_malloc0(maxlen+1);
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
	guint32 ret = 0;
	if(RAND_bytes((void *)&ret, sizeof(ret)) != 1) {
		JANUS_LOG(LOG_WARN, "Safe RAND_bytes() failed, falling back to unsafe PRNG\n");
		return g_random_int();
	}
	return ret;
}

guint64 janus_random_uint64_full(void) {
	guint64 ret = 0;
	if(RAND_bytes((void *)&ret, sizeof(ret)) != 1) {
		JANUS_LOG(LOG_WARN, "Safe RAND_bytes() failed, falling back to unsafe PRNG\n");
		return ((guint64)g_random_int() << 32) | g_random_int();
	}
	return ret;
}

guint64 janus_random_uint64(void) {
	return janus_random_uint64_full() & 0x1FFFFFFFFFFFFF;
}

char *janus_random_uuid(void) {
#if GLIB_CHECK_VERSION(2, 52, 0)
	return g_uuid_string_random();
#else
	/* g_uuid_string_random is only available from glib 2.52, so if it's
	 * not available we have to do it manually: the following code is
	 * heavily based on https://github.com/rxi/uuid4 (MIT license) */
	const char *template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
	const char *samples = "0123456789abcdef";
	union { unsigned char b[16]; uint64_t word[2]; } rnd;
	rnd.word[0] = janus_random_uint64_full();
	rnd.word[1] = janus_random_uint64_full();
	/* Generate the string */
	char uuid[37], *dst = uuid;
	const char *p = template;
	int i = 0, n = 0;
	while(*p) {
		n = rnd.b[i >> 1];
		n = (i & 1) ? (n >> 4) : (n & 0xf);
		switch (*p) {
			case 'x':
				*dst = samples[n];
				i++;
				break;
			case 'y':
				*dst = samples[(n & 0x3) + 8];
				i++;
				break;
			default:
				*dst = *p;
		}
		p++;
		dst++;
	}
	uuid[36] = '\0';
	return g_strdup(uuid);
#endif
}

guint64 *janus_uint64_dup(guint64 num) {
	guint64 *numdup = g_malloc(sizeof(guint64));
	*numdup = num;
	return numdup;
}

guint64 janus_uint64_hash(guint64 num) {
	num = (num ^ (num >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	num = (num ^ (num >> 27)) * UINT64_C(0x94d049bb133111eb);
	num = num ^ (num >> 31);
	return num;
}

int janus_string_to_uint8(const char *str, uint8_t *num) {
	if(str == NULL || num == NULL)
		return -EINVAL;
	long int val = strtol(str, 0, 10);
	if(val < 0 || val > UINT8_MAX)
		return -ERANGE;
	*num = val;
	return 0;
}

int janus_string_to_uint16(const char *str, uint16_t *num) {
	if(str == NULL || num == NULL)
		return -EINVAL;
	long int val = strtol(str, 0, 10);
	if(val < 0 || val > UINT16_MAX)
		return -ERANGE;
	*num = val;
	return 0;
}

int janus_string_to_uint32(const char *str, uint32_t *num) {
	if(str == NULL || num == NULL)
		return -EINVAL;
	long long int val = strtoll(str, 0, 10);
	if(val < 0 || val > UINT32_MAX)
		return -ERANGE;
	*num = val;
	return 0;
}

void janus_flags_reset(janus_flags *flags) {
	if(flags != NULL)
		g_atomic_pointer_set(flags, 0);
}

void janus_flags_set(janus_flags *flags, gsize flag) {
	if(flags != NULL) {
		g_atomic_pointer_or(flags, flag);
	}
}

void janus_flags_clear(janus_flags *flags, gsize flag) {
	if(flags != NULL) {
		g_atomic_pointer_and(flags, ~(flag));
	}
}

gboolean janus_flags_is_set(janus_flags *flags, gsize flag) {
	if(flags != NULL) {
		gsize bit = ((gsize) g_atomic_pointer_get(flags)) & flag;
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
			outgoing = tmp;
		}
		outgoing[strlen(outgoing)] = '\0';
		return outgoing;
	}
}

size_t janus_strlcat(char *dest, const char *src, size_t dest_size) {
	size_t ret = g_strlcat(dest, src, dest_size);
	if(ret >= dest_size)
		JANUS_LOG(LOG_ERR, "Truncation occurred, %lu >= %lu\n", ret, dest_size);
	return ret;
}

int janus_strlcat_fast(char *dest, const char *src, size_t dest_size, size_t *offset) {
	if(dest == NULL || src == NULL || offset == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid arguments\n");
		return -1;
	}
	if(*offset >= dest_size) {
		JANUS_LOG(LOG_ERR, "Offset is beyond the buffer size\n");
		return -2;
	}
	char *p = memccpy(dest + *offset, src, 0, dest_size - *offset);
	if(p == NULL) {
		JANUS_LOG(LOG_ERR, "Truncation occurred, %lu >= %lu\n",
			*offset + strlen(src), dest_size);
		*offset = dest_size;
		*(dest + dest_size -1) = '\0';
		return -3;
	}
	*offset = (p - dest - 1);
	return 0;
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

gchar *janus_make_absolute_path(const gchar *base_dir, const gchar *path) {
	if(!path)
		return NULL;
	if(g_path_is_absolute(path))
		return g_strdup(path);
	if(!base_dir)
		return NULL;
	return g_build_filename(base_dir, path, NULL);
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
	} else if(!strcasecmp(codec, "g722")) {
		/* We know the payload type is 9: we just need to make sure it's there */
		video = 0;
		format = "g722/8000";
		format2 = "G722/8000";
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
	} else if(!strcasecmp(codec, "av1")) {
		video = 1;
		format = "av1/90000";
		format2 = "AV1/90000";
	} else if(!strcasecmp(codec, "h265")) {
		video = 1;
		format = "h265/90000";
		format2 = "H265/90000";
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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
				if(sscanf(line, rtpmap, &pt) == 1) {
					*next = '\n';
					return pt;
				}
			} else if(strstr(line, "a=rtpmap") && strstr(line, format2)) {
				/* Gotcha! */
				int pt = 0;
				if(sscanf(line, rtpmap2, &pt) == 1) {
#pragma GCC diagnostic pop
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
	if(pt == 9)
		return "g722";
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
				if(sscanf(line, "a=rtpmap:%d %99s", &pt, name) == 2) {
					*next = '\n';
					if(strstr(name, "vp8") || strstr(name, "VP8"))
						return "vp8";
					if(strstr(name, "vp9") || strstr(name, "VP9"))
						return "vp9";
					if(strstr(name, "h264") || strstr(name, "H264"))
						return "h264";
					if(strstr(name, "av1") || strstr(name, "AV1"))
						return "av1";
					if(strstr(name, "h265") || strstr(name, "H265"))
						return "h265";
					if(strstr(name, "opus") || strstr(name, "OPUS"))
						return "opus";
					if(strstr(name, "pcmu") || strstr(name, "PCMU"))
						return "pcmu";
					if(strstr(name, "pcma") || strstr(name, "PCMA"))
						return "pcma";
					if(strstr(name, "g722") || strstr(name, "G722"))
						return "g722";
					if(strstr(name, "isac/16") || strstr(name, "ISAC/16"))
						return "isac16";
					if(strstr(name, "isac/32") || strstr(name, "ISAC/32"))
						return "isac32";
					if(strstr(name, "red"))
						return NULL;
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

/* PID file management */
static char *pidfile = NULL;
static int pidfd = -1;
static FILE *pidf = NULL;
int janus_pidfile_create(const char *file) {
	if(file == NULL)
		return 0;
	pidfile = g_strdup(file);
	/* Try creating a PID file (or opening an existing one) */
	pidfd = open(pidfile, O_RDWR|O_CREAT|O_TRUNC, 0644);
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
		JANUS_LOG(LOG_FATAL, "Error writing PID in file, error %d (%s)\n", errno, g_strerror(errno));
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

/* Protected folders management */
static GList *protected_folders = NULL;
static janus_mutex pf_mutex = JANUS_MUTEX_INITIALIZER;

void janus_protected_folder_add(const char *folder) {
	if(folder == NULL)
		return;
	janus_mutex_lock(&pf_mutex);
	protected_folders = g_list_append(protected_folders, g_strdup(folder));
	janus_mutex_unlock(&pf_mutex);
}

gboolean janus_is_folder_protected(const char *path) {
	/* We need a valid pathname (can't start with a space, we don't trim) */
	if(path == NULL || *path == ' ')
		return TRUE;
	/* Resolve the pathname to its real path first */
	char resolved[PATH_MAX+1];
	resolved[0] = '\0';
	if(realpath(path, resolved) == NULL && errno != ENOENT) {
		JANUS_LOG(LOG_ERR, "Error resolving path '%s'... %d (%s)\n",
			path, errno, g_strerror(errno));
		return TRUE;
	}
	/* Traverse the list of protected folders to see if any match */
	janus_mutex_lock(&pf_mutex);
	if(protected_folders == NULL) {
		/* No protected folder in the list */
		janus_mutex_unlock(&pf_mutex);
		return FALSE;
	}
	gboolean protected = FALSE;
	GList *temp = protected_folders;
	while(temp) {
		char *folder = (char *)temp->data;
		if(folder && (strstr(resolved, folder) == resolved)) {
			protected = TRUE;
			break;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&pf_mutex);
	return protected;
}

void janus_protected_folders_clear(void) {
	janus_mutex_lock(&pf_mutex);
	g_list_free_full(protected_folders, (GDestroyNotify)g_free);
	janus_mutex_unlock(&pf_mutex);
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
			janus_strlcat(type_name, "boolean", req_size);
			break;
		case JSON_INTEGER:
			janus_strlcat(type_name, "integer", req_size);
			break;
		case JSON_REAL:
			janus_strlcat(type_name, "real", req_size);
			break;
		case JSON_STRING:
			janus_strlcat(type_name, "string", req_size);
			break;
		case JSON_ARRAY:
			janus_strlcat(type_name, "array", req_size);
			break;
		case JSON_OBJECT:
			janus_strlcat(type_name, "object", req_size);
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

/* The following code is more related to codec specific helpers */
#if defined(__ppc__) || defined(__ppc64__)
	# define swap2(d)  \
	((d&0x000000ff)<<8) |  \
	((d&0x0000ff00)>>8)
#else
	# define swap2(d) d
#endif

gboolean janus_vp8_is_keyframe(const char *buffer, int len) {
	if(!buffer || len < 16)
		return FALSE;
	/* Parse VP8 header now */
	uint8_t vp8pd = *buffer;
	uint8_t xbit = (vp8pd & 0x80);
	uint8_t sbit = (vp8pd & 0x10);
	if(xbit) {
		JANUS_LOG(LOG_HUGE, "  -- X bit is set!\n");
		/* Read the Extended control bits octet */
		buffer++;
		vp8pd = *buffer;
		uint8_t ibit = (vp8pd & 0x80);
		uint8_t lbit = (vp8pd & 0x40);
		uint8_t tbit = (vp8pd & 0x20);
		uint8_t kbit = (vp8pd & 0x10);
		if(ibit) {
			JANUS_LOG(LOG_HUGE, "  -- I bit is set!\n");
			/* Read the PictureID octet */
			buffer++;
			vp8pd = *buffer;
			uint16_t picid = vp8pd, wholepicid = picid;
			uint8_t mbit = (vp8pd & 0x80);
			if(mbit) {
				JANUS_LOG(LOG_HUGE, "  -- M bit is set!\n");
				memcpy(&picid, buffer, sizeof(uint16_t));
				wholepicid = ntohs(picid);
				picid = (wholepicid & 0x7FFF);
				buffer++;
			}
			JANUS_LOG(LOG_HUGE, "  -- -- PictureID: %"SCNu16"\n", picid);
		}
		if(lbit) {
			JANUS_LOG(LOG_HUGE, "  -- L bit is set!\n");
			/* Read the TL0PICIDX octet */
			buffer++;
			vp8pd = *buffer;
		}
		if(tbit || kbit) {
			JANUS_LOG(LOG_HUGE, "  -- T/K bit is set!\n");
			/* Read the TID/KEYIDX octet */
			buffer++;
			vp8pd = *buffer;
		}
	}
	buffer++;	/* Now we're in the payload */
	if(sbit) {
		JANUS_LOG(LOG_HUGE, "  -- S bit is set!\n");
		unsigned long int vp8ph = 0;
		memcpy(&vp8ph, buffer, 4);
		vp8ph = ntohl(vp8ph);
		uint8_t pbit = ((vp8ph & 0x01000000) >> 24);
		if(!pbit) {
			JANUS_LOG(LOG_HUGE, "  -- P bit is NOT set!\n");
			/* It is a key frame! Get resolution for debugging */
			unsigned char *c = (unsigned char *)buffer+3;
			/* vet via sync code */
			if(c[0]!=0x9d||c[1]!=0x01||c[2]!=0x2a) {
				JANUS_LOG(LOG_HUGE, "First 3-bytes after header not what they're supposed to be?\n");
			} else {
				unsigned short val3, val5;
				memcpy(&val3,c+3,sizeof(short));
				int vp8w = swap2(val3)&0x3fff;
				int vp8ws = swap2(val3)>>14;
				memcpy(&val5,c+5,sizeof(short));
				int vp8h = swap2(val5)&0x3fff;
				int vp8hs = swap2(val5)>>14;
				JANUS_LOG(LOG_HUGE, "Got a VP8 key frame: %dx%d (scale=%dx%d)\n", vp8w, vp8h, vp8ws, vp8hs);
				return TRUE;
			}
		}
	}
	/* If we got here it's not a key frame */
	return FALSE;
}

gboolean janus_vp9_is_keyframe(const char *buffer, int len) {
	if(!buffer || len < 16)
		return FALSE;
	/* Parse VP9 header now */
	uint8_t vp9pd = *buffer;
	uint8_t ibit = (vp9pd & 0x80);
	uint8_t pbit = (vp9pd & 0x40);
	uint8_t lbit = (vp9pd & 0x20);
	uint8_t fbit = (vp9pd & 0x10);
	uint8_t vbit = (vp9pd & 0x02);
	buffer++;
	len--;
	if(ibit) {
		/* Read the PictureID octet */
		vp9pd = *buffer;
		uint16_t picid = vp9pd, wholepicid = picid;
		uint8_t mbit = (vp9pd & 0x80);
		if(!mbit) {
			buffer++;
			len--;
		} else {
			memcpy(&picid, buffer, sizeof(uint16_t));
			wholepicid = ntohs(picid);
			picid = (wholepicid & 0x7FFF);
			buffer += 2;
			len -= 2;
		}
	}
	if(lbit) {
		buffer++;
		len--;
		if(!fbit) {
			/* Non-flexible mode, skip TL0PICIDX */
			buffer++;
			len--;
		}
	}
	if(fbit && pbit) {
		/* Skip reference indices */
		uint8_t nbit = 1;
		while(nbit) {
			vp9pd = *buffer;
			nbit = (vp9pd & 0x01);
			buffer++;
			len--;
			if(len == 0)	/* Make sure we don't overflow */
				return FALSE;
		}
	}
	if(vbit) {
		/* Parse and skip SS */
		vp9pd = *buffer;
		uint n_s = (vp9pd & 0xE0) >> 5;
		n_s++;
		uint8_t ybit = (vp9pd & 0x10);
		if(ybit) {
			/* Iterate on all spatial layers and get resolution */
			buffer++;
			len--;
			if(len == 0)	/* Make sure we don't overflow */
				return FALSE;
			uint i=0;
			for(i=0; i<n_s && len>=4; i++,len-=4) {
				/* Width */
				uint16_t w;
				memcpy(&w, buffer, sizeof(uint16_t));
				int vp9w = ntohs(w);
				buffer += 2;
				/* Height */
				uint16_t h;
				memcpy(&h, buffer, sizeof(uint16_t));
				int vp9h = ntohs(h);
				buffer += 2;
				if(vp9w || vp9h) {
					JANUS_LOG(LOG_HUGE, "Got a VP9 key frame: %dx%d\n", vp9w, vp9h);
					return TRUE;
				}
			}
		}
	}
	/* If we got here it's not a key frame */
	return FALSE;
}

gboolean janus_h264_is_keyframe(const char *buffer, int len) {
	if(!buffer || len < 6)
		return FALSE;
	/* Parse H264 header now */
	uint8_t fragment = *buffer & 0x1F;
	uint8_t nal = *(buffer+1) & 0x1F;
	if(fragment == 7 || ((fragment == 28 || fragment == 29) && nal == 7)) {
		JANUS_LOG(LOG_HUGE, "Got an H264 key frame\n");
		return TRUE;
	} else if(fragment == 24) {
		/* May we find an SPS in this STAP-A? */
		buffer++;
		len--;
		uint16_t psize = 0;
		/* We're reading 3 bytes */
		while(len > 2) {
			memcpy(&psize, buffer, 2);
			psize = ntohs(psize);
			buffer += 2;
			len -= 2;
			int nal = *buffer & 0x1F;
			if(nal == 7) {
				JANUS_LOG(LOG_HUGE, "Got an SPS/PPS\n");
				return TRUE;
			}
			buffer += psize;
			len -= psize;
		}
	}
	/* If we got here it's not a key frame */
	return FALSE;
}

gboolean janus_av1_is_keyframe(const char *buffer, int len) {
	if(!buffer || len < 3)
		return FALSE;
	/* Read the aggregation header */
	uint8_t aggrh = *buffer;
	uint8_t zbit = (aggrh & 0x80) >> 7;
	uint8_t nbit = (aggrh & 0x08) >> 3;
	/* FIXME Ugly hack: we consider a packet with Z=0 and N=1 a keyframe */
	return (!zbit && nbit);
}

gboolean janus_h265_is_keyframe(const char *buffer, int len) {
	if(!buffer || len < 2)
		return FALSE;
	/* Parse the NAL unit */
	uint16_t unit = 0;
	memcpy(&unit, buffer, sizeof(uint16_t));
	unit = ntohs(unit);
	uint8_t type = (unit & 0x7E00) >> 9;
	if(type == 32 || type == 33 || type == 34 || type == 16 || type == 17 || type == 18 || type == 19 || type == 20 || type == 21) {
		/* FIXME We return TRUE for more than just VPS and SPS, as
		 * suggested in https://github.com/meetecho/janus-gateway/issues/2323 */
		return TRUE;
	}
	return FALSE;
}

int janus_vp8_parse_descriptor(char *buffer, int len,
		uint16_t *picid, uint8_t *tl0picidx, uint8_t *tid, uint8_t *y, uint8_t *keyidx) {
	if(!buffer || len < 6)
		return -1;
	if(picid)
		*picid = 0;
	if(tl0picidx)
		*tl0picidx = 0;
	if(tid)
		*tid = 0;
	if(y)
		*y = 0;
	if(keyidx)
		*keyidx = 0;
	uint8_t vp8pd = *buffer;
	uint8_t xbit = (vp8pd & 0x80);
	/* Read the Extended control bits octet */
	if(xbit) {
		buffer++;
		vp8pd = *buffer;
		uint8_t ibit = (vp8pd & 0x80);
		uint8_t lbit = (vp8pd & 0x40);
		uint8_t tbit = (vp8pd & 0x20);
		uint8_t kbit = (vp8pd & 0x10);
		if(ibit) {
			/* Read the PictureID octet */
			buffer++;
			vp8pd = *buffer;
			uint16_t partpicid = vp8pd, wholepicid = partpicid;
			uint8_t mbit = (vp8pd & 0x80);
			if(mbit) {
				memcpy(&partpicid, buffer, sizeof(uint16_t));
				wholepicid = ntohs(partpicid);
				partpicid = (wholepicid & 0x7FFF);
				buffer++;
			}
			if(picid)
				*picid = partpicid;
		}
		if(lbit) {
			/* Read the TL0PICIDX octet */
			buffer++;
			vp8pd = *buffer;
			if(tl0picidx)
				*tl0picidx = vp8pd;
		}
		if(tbit || kbit) {
			/* Read the TID/Y/KEYIDX octet */
			buffer++;
			vp8pd = *buffer;
			if(tid)
				*tid = (vp8pd & 0xC0) >> 6;
			if(y)
				*y = (vp8pd & 0x20) >> 5;
			if(keyidx)
				*keyidx = (vp8pd & 0x1F) >> 4;
		}
	}
	return 0;
}

static int janus_vp8_replace_descriptor(char *buffer, int len, uint16_t picid, uint8_t tl0picidx) {
	if(!buffer || len < 6)
		return -1;
	uint8_t vp8pd = *buffer;
	uint8_t xbit = (vp8pd & 0x80);
	/* Read the Extended control bits octet */
	if(xbit) {
		buffer++;
		vp8pd = *buffer;
		uint8_t ibit = (vp8pd & 0x80);
		uint8_t lbit = (vp8pd & 0x40);
		uint8_t tbit = (vp8pd & 0x20);
		uint8_t kbit = (vp8pd & 0x10);
		if(ibit) {
			/* Overwrite the PictureID octet */
			buffer++;
			vp8pd = *buffer;
			uint8_t mbit = (vp8pd & 0x80);
			if(!mbit) {
				*buffer = picid;
			} else {
				uint16_t wholepicid = htons(picid);
				memcpy(buffer, &wholepicid, 2);
				*buffer |= 0x80;
				buffer++;
			}
		}
		if(lbit) {
			/* Overwrite the TL0PICIDX octet */
			buffer++;
			*buffer = tl0picidx;
		}
		if(tbit || kbit) {
			/* Should we overwrite the TID/Y/KEYIDX octet? */
			buffer++;
		}
	}
	return 0;
}

void janus_vp8_simulcast_context_reset(janus_vp8_simulcast_context *context) {
	if(context == NULL)
		return;
	/* Reset the context values */
	context->last_picid = 0;
	context->base_picid = 0;
	context->base_picid_prev = 0;
	context->last_tlzi = 0;
	context->base_tlzi = 0;
	context->base_tlzi_prev = 0;
}

void janus_vp8_simulcast_descriptor_update(char *buffer, int len, janus_vp8_simulcast_context *context, gboolean switched) {
	if(!buffer || len < 0)
		return;
	uint16_t picid = 0;
	uint8_t tlzi = 0;
	uint8_t tid = 0;
	uint8_t ybit = 0;
	uint8_t keyidx = 0;
	/* Parse the identifiers in the VP8 payload descriptor */
	if(janus_vp8_parse_descriptor(buffer, len, &picid, &tlzi, &tid, &ybit, &keyidx) < 0)
		return;
	if(switched) {
		context->base_picid_prev = context->last_picid;
		context->base_picid = picid;
		context->base_tlzi_prev = context->last_tlzi;
		context->base_tlzi = tlzi;
	}
	context->last_picid = (picid-context->base_picid)+context->base_picid_prev+1;
	context->last_tlzi = (tlzi-context->base_tlzi)+context->base_tlzi_prev+1;
	/* Overwrite the values in the VP8 payload descriptors with the ones we have */
	janus_vp8_replace_descriptor(buffer, len, context->last_picid, context->last_tlzi);
}

/* Helper method to parse a VP9 RTP video frame and get some SVC-related info:
 * notice that this only works with VP9, right now, on an experimental basis */
int janus_vp9_parse_svc(char *buffer, int len, gboolean *found, janus_vp9_svc_info *info) {
	if(!buffer || len < 8)
		return -1;
	/* VP9 depay: */
		/* https://tools.ietf.org/html/draft-ietf-payload-vp9-04 */
	/* Read the first octet (VP9 Payload Descriptor) */
	uint8_t vp9pd = *buffer;
	uint8_t ibit = (vp9pd & 0x80) >> 7;
	uint8_t pbit = (vp9pd & 0x40) >> 6;
	uint8_t lbit = (vp9pd & 0x20) >> 5;
	uint8_t fbit = (vp9pd & 0x10) >> 4;
	uint8_t bbit = (vp9pd & 0x08) >> 3;
	uint8_t ebit = (vp9pd & 0x04) >> 2;
	uint8_t vbit = (vp9pd & 0x02) >> 1;
	if(!lbit) {
		/* No Layer indices present, no need to go on */
		if(found)
			*found = FALSE;
		return 0;
	}
	/* Move to the next octet and see what's there */
	buffer++;
	len--;
	if(ibit) {
		/* Read the PictureID octet */
		vp9pd = *buffer;
		uint16_t picid = vp9pd, wholepicid = picid;
		uint8_t mbit = (vp9pd & 0x80);
		if(!mbit) {
			buffer++;
			len--;
		} else {
			memcpy(&picid, buffer, sizeof(uint16_t));
			wholepicid = ntohs(picid);
			picid = (wholepicid & 0x7FFF);
			buffer += 2;
			len -= 2;
		}
	}
	if(lbit) {
		/* Read the octet and parse the layer indices now */
		vp9pd = *buffer;
		int tlid = (vp9pd & 0xE0) >> 5;
		uint8_t ubit = (vp9pd & 0x10) >> 4;
		int slid = (vp9pd & 0x0E) >> 1;
		uint8_t dbit = (vp9pd & 0x01);
		JANUS_LOG(LOG_HUGE, "%s Mode, Layer indices: Temporal: %d (u=%u), Spatial: %d (d=%u)\n",
			fbit ? "Flexible" : "Non-flexible", tlid, ubit, slid, dbit);
		if(info) {
			info->temporal_layer = tlid;
			info->spatial_layer = slid;
			info->fbit = fbit;
			info->pbit = pbit;
			info->dbit = dbit;
			info->ubit = ubit;
			info->bbit = bbit;
			info->ebit = ebit;
		}
		if(found)
			*found = TRUE;
		/* Go on, just to get to the SS, if available (which we currently ignore anyway) */
		buffer++;
		len--;
		if(!fbit) {
			/* Non-flexible mode, skip TL0PICIDX */
			buffer++;
			len--;
		}
	}
	if(fbit && pbit) {
		/* Skip reference indices */
		uint8_t nbit = 1;
		while(nbit) {
			vp9pd = *buffer;
			nbit = (vp9pd & 0x01);
			buffer++;
			len--;
			if(len == 0)	/* Make sure we don't overflow */
				return -1;
		}
	}
	if(vbit) {
		/* Parse and skip SS */
		vp9pd = *buffer;
		int n_s = (vp9pd & 0xE0) >> 5;
		n_s++;
		JANUS_LOG(LOG_HUGE, "There are %d spatial layers\n", n_s);
		uint8_t ybit = (vp9pd & 0x10);
		uint8_t gbit = (vp9pd & 0x08);
		if(ybit) {
			/* Iterate on all spatial layers and get resolution */
			buffer++;
			len--;
			if(len == 0)	/* Make sure we don't overflow */
				return -1;
			int i=0;
			for(i=0; i<n_s; i++) {
				/* Been there, done that: skip skip skip */
				buffer += 4;
				len -= 4;
				if(len <= 0)	/* Make sure we don't overflow */
					return -1;
			}
		}
		if(gbit) {
			if(!ybit) {
				buffer++;
				len--;
				if(len == 0)	/* Make sure we don't overflow */
					return -1;
			}
			uint8_t n_g = *buffer;
			JANUS_LOG(LOG_HUGE, "There are %u frames in a GOF\n", n_g);
			buffer++;
			len--;
			if(len == 0)	/* Make sure we don't overflow */
				return -1;
			if(n_g > 0) {
				int i=0;
				for(i=0; i<n_g; i++) {
					/* Read the R bits */
					vp9pd = *buffer;
					int r = (vp9pd & 0x0C) >> 2;
					if(r > 0) {
						/* Skip reference indices */
						buffer += r;
						len -= r;
						if(len <= 0)	/* Make sure we don't overflow */
							return -1;
					}
					buffer++;
					len--;
					if(len == 0)	/* Make sure we don't overflow */
						return -1;
				}
			}
		}
	}
	return 0;
}

/* RED parsing and building utilities */
GList *janus_red_parse_blocks(char *buffer, int len) {
	if(buffer == NULL || len < 0)
		return NULL;
	/* TODO This whole method should be fuzzed */
	char *payload = buffer;
	int plen = len;
	/* Find out how many generations are in the RED packet */
	int gens = 0;
	uint32_t red_block;
	uint8_t follow = 0, block_pt = 0;
	uint16_t ts_offset = 0, block_len = 0;
	GList *blocks = NULL;
	janus_red_block *rb = NULL;
	/* Parse the header */
	while(payload != NULL && plen > 0) {
		/* Go through the header for the different generations */
		gens++;
		follow = ((*payload) & 0x80) >> 7;
		block_pt = (*payload) & 0x7F;
		if(follow && plen > 3) {
			/* Read the rest of the header */
			memcpy(&red_block, payload, sizeof(red_block));
			red_block = ntohl(red_block);
			ts_offset = (red_block & 0x00FFFC00) >> 10;
			block_len = (red_block & 0x000003FF);
			JANUS_LOG(LOG_HUGE, "  [%d] f=%u, pt=%u, tsoff=%"SCNu16", blen=%"SCNu16"\n",
				gens, follow, block_pt, ts_offset, block_len);
			rb = g_malloc0(sizeof(janus_red_block));
			rb->pt = block_pt;
			rb->ts_offset = ts_offset;
			rb->length = block_len;
			blocks = g_list_append(blocks, rb);
			payload += 4;
			plen -= 4;
		} else {
			/* Header parsed */
			payload++;
			plen--;
			JANUS_LOG(LOG_HUGE, "  [%d] f=%u, pt=%u, tsoff=0, blen=TBD.\n",
				gens, follow, block_pt);
			break;
		}
	}
	/* Go through the blocks, iterating on the lengths to get a pointer to the data */
	if(blocks != NULL) {
		int tot_gens = gens;
		gens = 0;
		uint16_t length = 0;
		GList *temp = blocks;
		while(temp != NULL) {
			gens++;
			tot_gens--;
			rb = (janus_red_block *)temp->data;
			length = rb->length;
			if(length > plen) {
				JANUS_LOG(LOG_WARN, "  >> [%d] Broken red payload:\n", gens);
				g_list_free_full(blocks, (GDestroyNotify)g_free);
				return NULL;
			}
			if(length > 0) {
				/* Redundant data, take note of where the block is */
				JANUS_LOG(LOG_HUGE, "  >> [%d] plen=%"SCNu16"\n", gens, length);
				rb->data = (uint8_t *)payload;
				payload += length;
				plen -= length;
			}
			temp = temp->next;
		}
	}
	if(plen > 0) {
		/* The last block is the primary data, add it to the list */
		gens++;
		JANUS_LOG(LOG_HUGE, "  >> [%d] plen=%d\n", gens, plen);
		rb = g_malloc0(sizeof(janus_red_block));
		rb->pt = block_pt;
		rb->length = plen;
		rb->data = (uint8_t *)payload;
		blocks = g_list_append(blocks, rb);
	}

	return blocks;
}
int janus_red_pack_blocks(char *buffer, int len, GList *blocks) {
	if(buffer == NULL || len < 0)
		return 1;
	int required = 0, written = 0;
	janus_red_block *rb = NULL;
	/* Write all headers to the buffer */
	uint32_t red_block = 0;
	uint8_t *payload = (uint8_t *)buffer;
	GList *temp = blocks;
	while(temp != NULL) {
		rb = (janus_red_block *)temp->data;
		required += (temp->next ? 4 : 1);
		required += rb->length;
		if(len < required) {
			JANUS_LOG(LOG_ERR, "RED buffer too small (%d bytes, at least %d needed)\n", len, required);
			return -2;
		}
		if(temp->next != NULL) {
			/* There's going to be a follow-up, write 4 bytes (F=1 and info) */
			red_block =
				0x80000000 +							/* F=1 */
				(0x7F000000 & (rb->pt << 24)) + 		/* Payload type */
				(0x00FFFC00 & (rb->ts_offset << 10)) + 	/* Timestamp offset */
				(0x000003FF & rb->length);				/* Data length */
			red_block = htonl(red_block);
			memcpy(payload + written, &red_block, sizeof(red_block));
			written += 4;
		} else {
			/* Primary data, 1 byte (F=0 and payload type) */
			uint8_t pt = rb->pt;
			*(payload + written) = pt;
			written++;
		}
		temp = temp->next;
	}
	/* Now write all data to the buffer too */
	temp = blocks;
	while(temp != NULL) {
		rb = (janus_red_block *)temp->data;
		/* Write the data itself */
		memcpy(payload + written, rb->data, rb->length);
		written += rb->length;
		temp = temp->next;
	}
	return written;
}
int janus_red_replace_block_pt(char *buffer, int len, int pt) {
	if(buffer == NULL || len < 0 || pt < 0 || pt > 127)
		return -1;
	/* TODO This whole method should be fuzzed */
	char *payload = buffer;
	int plen = len;
	uint8_t follow = 0;
	/* Parse the header */
	while(payload != NULL && plen > 0) {
		/* Go through the block headers */
		follow = ((*payload) & 0x80) >> 7;
		*payload = (0x80 & (follow << 7)) + (0x7F & pt);
		if(follow && plen > 3) {
			/* Move to the next block header */
			payload += 4;
			plen -= 4;
		} else {
			/* We're done */
			break;
		}
	}
	return 0;
}

/* Bit manipulation (mostly for TWCC) */
inline guint32 janus_push_bits(guint32 word, size_t num, guint32 val) {
	if(num == 0)
		return word;
	return (word << num) | (val & (0xFFFFFFFF>>(32-num)));
}

inline void janus_set1(guint8 *data,size_t i,guint8 val) {
	data[i] = val;
}

inline void janus_set2(guint8 *data,size_t i,guint32 val) {
	data[i+1] = (guint8)(val);
	data[i]   = (guint8)(val>>8);
}

inline void janus_set3(guint8 *data,size_t i,guint32 val) {
	data[i+2] = (guint8)(val);
	data[i+1] = (guint8)(val>>8);
	data[i]   = (guint8)(val>>16);
}

inline void janus_set4(guint8 *data,size_t i,guint32 val) {
	data[i+3] = (guint8)(val);
	data[i+2] = (guint8)(val>>8);
	data[i+1] = (guint8)(val>>16);
	data[i]   = (guint8)(val>>24);
}

uint8_t janus_bitstream_getbit(uint8_t *base, uint32_t offset) {
	return ((*(base + (offset >> 0x3))) >> (0x7 - (offset & 0x7))) & 0x1;
}

uint32_t janus_bitstream_getbits(uint8_t *base, uint8_t num, uint32_t *offset) {
	uint32_t res = 0;
	int32_t i = 0;
	for(i=num-1; i>=0; i--) {
		res |= janus_bitstream_getbit(base, (*offset)++) << i;
	}
	return res;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
size_t janus_gzip_compress(int compression, char *text, size_t tlen, char *compressed, size_t zlen) {
	if(text == NULL || tlen < 1 || compressed == NULL || zlen < 1)
		return -1;
	if(compression < 0 || compression > 9) {
		JANUS_LOG(LOG_WARN, "Invalid compression factor %d, falling back to default compression...\n", compression);
		compression = Z_DEFAULT_COMPRESSION;
	}

	/* Initialize the deflater, and clarify we need gzip */
	z_stream zs = { 0 };
	zs.zalloc = Z_NULL;
	zs.zfree = Z_NULL;
	zs.opaque = Z_NULL;
	zs.next_in = (Bytef *)text;
	zs.avail_in = (uInt)tlen;
	zs.next_out = (Bytef *)compressed;
	zs.avail_out = (uInt)zlen;
	int res = deflateInit2(&zs, compression, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
	if(res != Z_OK) {
		JANUS_LOG(LOG_ERR, "deflateInit error: %d\n", res);
		return 0;
	}
	/* Deflate the string */
	res = deflate(&zs, Z_FINISH);
	if(res != Z_STREAM_END) {
		JANUS_LOG(LOG_ERR, "deflate error: %d\n", res);
		return 0;
	}
	res = deflateEnd(&zs);
	if(res != Z_OK) {
		JANUS_LOG(LOG_ERR, "deflateEnd error: %d\n", res);
		return 0;
	}

	/* Done, return the size of the compressed data */
	return zs.total_out;
}
#endif
