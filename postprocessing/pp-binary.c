/*! \file    pp-binary.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate binary files out of binary data recordings
 * \details  Implementation of the post-processing code needed to
 * generate binary files out of binary data recordings: more precisely,
 * the code simply extracts the data from the packets and appends it to
 * the provided file exactly as it is, with no header/footer.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "pp-binary.h"
#include "../debug.h"


FILE *binary_file = NULL;

/* Processing methods */
int janus_pp_binary_create(char *destination, char *metadata) {
	/* Create the file */
	binary_file = fopen(destination, "wb");
	if(binary_file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		return -1;
	}
	/* Note: we're creating a binary file whose only content will be the
	 * binary data messages, so there's no way we can add a text prefix,
	 * header or intro, and nothing we can do with the metadata either */

	return 0;
}

int janus_pp_binary_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working || !binary_file)
		return -1;
	janus_pp_frame_packet *tmp = list;
	uint bytes = 0;
	uint16_t bufsize = 1500;
	uint8_t *buffer = g_malloc0(bufsize);

	while(*working && tmp != NULL) {
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked text packet (time ~%"SCNu64"s)\n", tmp->ts);
			tmp = tmp->next;
			continue;
		}
		/* Let's read the content and write it to the file */
		fseek(file, tmp->offset, SEEK_SET);
		JANUS_LOG(LOG_VERB, "Reading %d bytes...\n", tmp->len);
		uint16_t total = tmp->len;
		while(total > 0) {
			bytes = fread(buffer, sizeof(char), total > bufsize ? bufsize : total, file);
			if(bytes == 0) {
				JANUS_LOG(LOG_ERR, "Error reading from file...\n");
				break;
			}
			JANUS_LOG(LOG_VERB, "Read %d bytes...\n", bytes);
			if(fwrite(buffer, sizeof(char), bytes, binary_file) != bytes) {
				JANUS_LOG(LOG_ERR, "Couldn't write all the buffer...\n");
			}
			total -= bytes;
		}
		fflush(binary_file);
		/* Next? */
		tmp = tmp->next;
	}
	g_free(buffer);

	return 0;
}

void janus_pp_binary_close(void) {
	/* Flush and close file */
	if(binary_file != NULL) {
		fflush(binary_file);
		fclose(binary_file);
	}
	binary_file = NULL;
}
