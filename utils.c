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

gint64 janus_get_monotonic_time() {
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

/* Easy way to replace multiple occurrences of a string with another: MAY creates a NEW string */
char *janus_string_replace(char *message, char *old, char *new, int *modified)
{
	if(!message || !old || !new || !modified)
		return NULL;
	*modified = 0;
	if(!strstr(message, old)) {	/* Nothing to be done (old is not there) */
		return message;
	}
	if(!strcmp(old, new)) {	/* Nothing to be done (old=new) */
		return message;
	}
	if(strlen(old) == strlen(new)) {	/* Just overwrite */
		char *outgoing = message;
		char *pos = strstr(outgoing, old), *tmp = NULL;
		int i = 0;
		while(pos) {
			i++;
			memcpy(pos, new, strlen(new));
			pos += strlen(old);
			tmp = strstr(pos, old);
			pos = tmp;
		}
		return outgoing;
	} else {	/* We need to resize */
		*modified = 1;
		char *outgoing = strdup(message);
		if(outgoing == NULL) {
			return NULL;
		}
		int diff = strlen(new) - strlen(old);
		/* Count occurrences */
		int counter = 0;
		char *pos = strstr(outgoing, old), *tmp = NULL;
		while(pos) {
			counter++;
			pos += strlen(old);
			tmp = strstr(pos, old);
			pos = tmp;
		}
		uint16_t oldlen = strlen(outgoing)+1, newlen = oldlen + diff*counter;
		*modified = diff*counter;
		if(diff > 0) {	/* Resize now */
			tmp = realloc(outgoing, newlen);
			if(!tmp)
				return NULL;
			outgoing = tmp;
		}
		/* Replace string */
		pos = strstr(outgoing, old);
		while(pos) {
			if(diff > 0) {	/* Move to the right (new is larger than old) */
				uint16_t len = strlen(pos)+1;
				memmove(pos + diff, pos, len);
				memcpy(pos, new, strlen(new));
				pos += strlen(new);
				tmp = strstr(pos, old);
			} else {	/* Move to the left (new is smaller than old) */
				uint16_t len = strlen(pos - diff)+1;
				memmove(pos, pos - diff, len);
				memcpy(pos, new, strlen(new));
				pos += strlen(old);
				tmp = strstr(pos, old);
			}
			pos = tmp;
		}
		if(diff < 0) {	/* We skipped the resize previously (shrinking memory) */
			tmp = realloc(outgoing, newlen);
			if(!tmp)
				return NULL;
			outgoing = tmp;
		}
		outgoing[strlen(outgoing)] = '\0';
		return outgoing;
	}
}
