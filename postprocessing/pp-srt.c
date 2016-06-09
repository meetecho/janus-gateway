/*! \file    pp-srt.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .srt files
 * \details  Implementation of the post-processing code needed to
 * generate .srt files out of text data recordings.
 * 
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "pp-srt.h"
#include "../debug.h"


FILE *srt_file = NULL;

/* Helper method to print times */
static void janus_pp_srt_format_time(char *buffer, int len, guint64 when) {
	gint64 seconds = when/G_USEC_PER_SEC;
	gint64 ms = (when/1000)-seconds*1000;
	gint64 minutes = seconds/60;
	seconds -= minutes*60;
	gint64 hours = minutes/60;
	minutes -= hours*60;
	g_snprintf(buffer, len, "%02"SCNi64":%02"SCNi64":%02"SCNi64".%03"SCNi64, hours, minutes, seconds, ms);
}

/* Processing methods */
int janus_pp_srt_create(char *destination) {
	/* Create srt file */
	srt_file = fopen(destination, "wb");
	if(srt_file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		return -1;
	}

	/* TODO Any header? */

	return 0;
}

int janus_pp_srt_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	int seq = 0;
	int bytes = 0;
	uint8_t *buffer = g_malloc0(1500);
	char srt_buffer[2048], from[20], to[20];
	size_t buflen = 0;

	while(*working && tmp != NULL) {
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked text packet (time ~%"SCNu64"s)\n", tmp->ts);
			tmp = tmp->next;
			continue;
		}
		fseek(file, tmp->offset, SEEK_SET);
		bytes = fread(buffer, sizeof(char), tmp->len, file);
		if(bytes != tmp->len)
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, tmp->len);
		*(buffer+bytes) = '\0';
		/* Increase sequence number */
		seq++;
		/* Compute from/to times */
		janus_pp_srt_format_time(from, sizeof(from), tmp->ts);
		if(tmp->next)
			janus_pp_srt_format_time(to, sizeof(from), tmp->next->ts-1000);
		else
			janus_pp_srt_format_time(to, sizeof(from), tmp->ts + 5*G_USEC_PER_SEC);
		/* Write the lines */
		g_snprintf(srt_buffer, 2048, "%d\n%s --> %s\n%s\n\n", seq, from, to, buffer);
		if(srt_file != NULL) {
			buflen = strlen(srt_buffer);
			if(fwrite(srt_buffer, sizeof(char), buflen, srt_file) != buflen) {
				JANUS_LOG(LOG_ERR, "Couldn't write text...\n");
			}
			fflush(srt_file);
		}
		tmp = tmp->next;
	}
	g_free(buffer);

	return 0;
}

void janus_pp_srt_close(void) {
	/* Flush and close file */
	if(srt_file != NULL) {
		fflush(srt_file);
		fclose(srt_file);
	}
	srt_file = NULL;
}
