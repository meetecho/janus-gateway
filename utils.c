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
#include "utils.h"

gint64 janus_get_monotonic_time(void) {
	struct timespec ts;
	clock_gettime (CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec*G_GINT64_CONSTANT(1000000)) + (ts.tv_nsec/G_GINT64_CONSTANT(1000));
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
		char *outgoing = strdup(message);
		free(message);
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
			tmp = realloc(outgoing, new_stringlen);
			if(!tmp) {
				free(outgoing);
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
			tmp = realloc(outgoing, new_stringlen);
			if(!tmp) {
				free(outgoing);
				return NULL;
			}
			outgoing = tmp;
		}
		outgoing[strlen(outgoing)] = '\0';
		return outgoing;
	}
}
