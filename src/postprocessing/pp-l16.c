/*! \file    pp-l16.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .wav files out of L16 frames (headers)
 * \details  Implementation of the post-processing code needed to
 * generate raw .wav files out of L16 RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#if defined(__MACH__) || defined(__FreeBSD__)
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "pp-l16.h"
#include "../debug.h"


/* WAV header */
typedef struct janus_pp_l16_wav {
	char riff[4];
	uint32_t len;
	char wave[4];
	char fmt[4];
	uint32_t formatsize;
	uint16_t format;
	uint16_t channels;
	uint32_t samplerate;
	uint32_t avgbyterate;
	uint16_t samplebytes;
	uint16_t channelbits;
	char data[4];
	uint32_t blocksize;
} janus_pp_l16_wav;
static FILE *wav_file = NULL;

/* Supported target formats */
static const char *janus_pp_l16_formats[] = {
	"wav", NULL
};
const char **janus_pp_l16_get_extensions(void) {
	return janus_pp_l16_formats;
}

/* Processing methods */
static int samplerate = 0;
int janus_pp_l16_create(char *destination, int rate, char *metadata) {
	samplerate = rate;
	if(samplerate != 16000 && samplerate != 48000) {
		JANUS_LOG(LOG_ERR, "Unsupported sample rate %d (should be 16000 or 48000)\n", rate);
		return -1;
	}
	/* Create wav file */
	wav_file = fopen(destination, "wb");
	if(wav_file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		return -1;
	}
	/* Add header */
	JANUS_LOG(LOG_INFO, "Writing .wav file header\n");
	janus_pp_l16_wav header = {
		{'R', 'I', 'F', 'F'},
		0,
		{'W', 'A', 'V', 'E'},
		{'f', 'm', 't', ' '},
		16,
		1,
		1,
		samplerate,
		samplerate * 2,
		2,
		16,
		{'d', 'a', 't', 'a'},
		0
	};
	/* Note: .wav files don't seem to support arbitrary comments
	 * so there's nothing we can do with the provided metadata*/
	if(fwrite(&header, 1, sizeof(header), wav_file) != sizeof(header)) {
		JANUS_LOG(LOG_ERR, "Couldn't write WAV header, expect problems...\n");
	}
	fflush(wav_file);
	return 0;
}

int janus_pp_l16_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	long int offset = 0;
	int bytes = 0, len = 0, steps = 0, last_seq = 0;
	uint8_t *buffer = g_malloc0(1500);
	int16_t samples[1500];
	memset(samples, 0, sizeof(samples));
	size_t num_samples = samplerate/100/2;
	int sr = samplerate/1000;
	while(*working && tmp != NULL) {
		if(tmp->prev != NULL && ((tmp->ts - tmp->prev->ts)/sr/10 > 1)) {
			JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
				tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/samplerate);
			int silence_count = (tmp->ts - tmp->prev->ts)/sr/10 - 1;
			int i=0;
			for(i=0; i<silence_count; i++) {
				JANUS_LOG(LOG_WARN, "[FILL] Writing silence (seq=%d, index=%d)\n",
					tmp->prev->seq+i+1, i+1);
				/* Add silence */
				memset(samples, 0, num_samples*2);
				if(wav_file != NULL) {
					if(fwrite(samples, sizeof(char), num_samples*2, wav_file) != num_samples) {
						JANUS_LOG(LOG_ERR, "Couldn't write sample...\n");
					}
					fflush(wav_file);
				}
			}
		}
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked audio packet (time ~%"SCNu64"s)\n", (tmp->ts-list->ts)/8000);
			tmp = tmp->next;
			continue;
		}
		if(tmp->audiolevel != -1) {
			JANUS_LOG(LOG_VERB, "Audio level: %d dB\n", tmp->audiolevel);
		}
		guint16 diff = tmp->prev == NULL ? 1 : (tmp->seq - tmp->prev->seq);
		len = 0;
		/* RTP payload */
		offset = tmp->offset+12+tmp->skip;
		fseek(file, offset, SEEK_SET);
		len = tmp->len-12-tmp->skip;
		if(len < 1) {
			tmp = tmp->next;
			continue;
		}
		bytes = fread(buffer, sizeof(char), len, file);
		if(bytes != len) {
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
			tmp = tmp->next;
			continue;
		}
		if(last_seq == 0)
			last_seq = tmp->seq;
		if(tmp->seq < last_seq) {
			last_seq = tmp->seq;
			steps++;
		}
		JANUS_LOG(LOG_VERB, "Writing %d bytes out of %d (seq=%"SCNu16", step=%"SCNu16", ts=%"SCNu64", time=%"SCNu64"s)\n",
			bytes, tmp->len, tmp->seq, diff, tmp->ts, (tmp->ts-list->ts)/samplerate);
		num_samples = bytes/2;
		int i=0;
		for(i=0; i<(int)num_samples; i++) {
			memcpy(&samples[i], buffer + i*2, sizeof(int16_t));
			samples[i] = ntohs(samples[i]);
		}
		if(wav_file != NULL) {
			if(fwrite(samples, sizeof(int16_t), num_samples, wav_file) != num_samples) {
				JANUS_LOG(LOG_ERR, "Couldn't write sample...\n");
			}
			fflush(wav_file);
		}
		tmp = tmp->next;
	}
	g_free(buffer);
	return 0;
}

void janus_pp_l16_close(void) {
	/* Flush and close file */
	if(wav_file != NULL) {
		/* Update the header */
		fseek(wav_file, 0, SEEK_END);
		uint32_t size = ftell(wav_file) - 8;
		fseek(wav_file, 4, SEEK_SET);
		fwrite(&size, sizeof(uint32_t), 1, wav_file);
		size += 8;
		fseek(wav_file, 40, SEEK_SET);
		fwrite(&size, sizeof(uint32_t), 1, wav_file);
		fflush(wav_file);
		fclose(wav_file);
	}
	wav_file = NULL;
}
